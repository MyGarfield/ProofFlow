#!/usr/bin/env node

import { spawn } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";

const VIEWPORTS = Object.freeze([
  { height: 812, label: "375x812", mobile: true, width: 375 },
  { height: 720, label: "1280x720", mobile: false, width: 1280 },
  { height: 900, label: "1440x900", mobile: false, width: 1440 },
]);

function parseArguments(argv) {
  const options = {
    chrome: process.env.PROOFFLOW_CHROME_BIN || "",
    outputDirectory: "",
    url: "http://127.0.0.1:4173/",
  };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    const value = argv[index + 1];
    if (argument === "--chrome" && value) {
      options.chrome = value;
      index += 1;
    } else if (argument === "--output-dir" && value) {
      options.outputDirectory = value;
      index += 1;
    } else if (argument === "--url" && value) {
      options.url = value;
      index += 1;
    } else {
      throw new Error(`unknown or incomplete argument: ${argument}`);
    }
  }
  if (!options.outputDirectory) {
    throw new Error("--output-dir is required");
  }
  if (!/^http:\/\/127\.0\.0\.1:\d+\/(?:[^?#]*)?$/.test(options.url)) {
    throw new Error("--url must be an explicit 127.0.0.1 HTTP URL");
  }
  if (!options.chrome) {
    options.chrome = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
  }
  return options;
}

class CdpClient {
  constructor(webSocketUrl) {
    this.nextId = 1;
    this.pending = new Map();
    this.eventWaiters = new Map();
    this.socket = new WebSocket(webSocketUrl);
  }

  async open() {
    await new Promise((resolve, reject) => {
      const timeout = setTimeout(() => reject(new Error("CDP WebSocket open timeout")), 10000);
      this.socket.addEventListener(
        "open",
        () => {
          clearTimeout(timeout);
          resolve();
        },
        { once: true },
      );
      this.socket.addEventListener(
        "error",
        () => {
          clearTimeout(timeout);
          reject(new Error("CDP WebSocket open failed"));
        },
        { once: true },
      );
      this.socket.addEventListener("message", (event) => this.receive(event.data));
    });
  }

  receive(raw) {
    const message = JSON.parse(raw);
    if (message.id) {
      const pending = this.pending.get(message.id);
      if (!pending) {
        return;
      }
      this.pending.delete(message.id);
      if (message.error) {
        pending.reject(new Error(`${pending.method}: ${message.error.message}`));
      } else {
        pending.resolve(message.result);
      }
      return;
    }
    const waiters = this.eventWaiters.get(message.method) || [];
    this.eventWaiters.delete(message.method);
    waiters.forEach((waiter) => waiter.resolve(message.params));
  }

  send(method, params = {}) {
    const id = this.nextId;
    this.nextId += 1;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { method, reject, resolve });
      this.socket.send(JSON.stringify({ id, method, params }));
    });
  }

  waitFor(method, timeoutMilliseconds = 10000) {
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(new Error(`CDP event timeout: ${method}`));
      }, timeoutMilliseconds);
      const waiter = {
        reject,
        resolve: (value) => {
          clearTimeout(timeout);
          resolve(value);
        },
      };
      const waiters = this.eventWaiters.get(method) || [];
      waiters.push(waiter);
      this.eventWaiters.set(method, waiters);
    });
  }

  close() {
    this.socket.close();
  }
}

async function browserWebSocket(browserProcess) {
  return await new Promise((resolve, reject) => {
    let stderr = "";
    const timeout = setTimeout(() => {
      reject(new Error(`Chrome DevTools startup timeout\n${stderr.slice(-2000)}`));
    }, 15000);
    browserProcess.stderr.setEncoding("utf8");
    browserProcess.stderr.on("data", (chunk) => {
      stderr += chunk;
      const match = stderr.match(/DevTools listening on (ws:\/\/[^\s]+)/);
      if (match) {
        clearTimeout(timeout);
        resolve(match[1]);
      }
    });
    browserProcess.once("exit", (code) => {
      clearTimeout(timeout);
      reject(new Error(`Chrome exited before DevTools was ready: ${code}\n${stderr}`));
    });
  });
}

async function createTarget(debuggingPort) {
  const response = await fetch(`http://127.0.0.1:${debuggingPort}/json/new?about%3Ablank`, {
    method: "PUT",
  });
  if (!response.ok) {
    throw new Error(`cannot create Chrome target: HTTP ${response.status}`);
  }
  return await response.json();
}

async function closeTarget(debuggingPort, targetId) {
  await fetch(`http://127.0.0.1:${debuggingPort}/json/close/${targetId}`);
}

async function inspectViewport({ debuggingPort, outputDirectory, url, viewport }) {
  const target = await createTarget(debuggingPort);
  const client = new CdpClient(target.webSocketDebuggerUrl);
  await client.open();
  try {
    await client.send("Page.enable");
    await client.send("Runtime.enable");
    await client.send("Network.enable");
    await client.send("Emulation.setDeviceMetricsOverride", {
      deviceScaleFactor: 1,
      height: viewport.height,
      mobile: viewport.mobile,
      screenHeight: viewport.height,
      screenWidth: viewport.width,
      width: viewport.width,
    });
    await client.send("Emulation.setEmulatedMedia", {
      features: [{ name: "prefers-reduced-motion", value: "reduce" }],
      media: "screen",
    });
    const loaded = client.waitFor("Page.loadEventFired");
    const navigation = await client.send("Page.navigate", { url });
    if (navigation.errorText) {
      throw new Error(`navigation failed: ${navigation.errorText}`);
    }
    await loaded;
    await client.send("Runtime.evaluate", {
      awaitPromise: true,
      expression: "new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve)))",
    });

    const evaluation = await client.send("Runtime.evaluate", {
      expression: `(() => {
        const root = document.documentElement;
        const interactive = [...document.querySelectorAll('a[href], input[type="range"]')]
          .filter((node) => {
            const style = getComputedStyle(node);
            return style.display !== 'none' && style.visibility !== 'hidden';
          })
          .map((node) => {
            const rect = node.getBoundingClientRect();
            return {
              height: Math.round(rect.height * 100) / 100,
              label: node.getAttribute('aria-label') || node.textContent.trim().slice(0, 80),
              tag: node.tagName,
              width: Math.round(rect.width * 100) / 100,
            };
          });
        const fragmentErrors = [...document.querySelectorAll('a[href^="#"]')]
          .map((anchor) => anchor.getAttribute('href').slice(1))
          .filter((id) => id && !document.getElementById(id));
        const resources = performance.getEntriesByType('resource').map((entry) => entry.name);
        const slider = document.querySelector('#story-scrubber');
        slider.value = '75';
        slider.dispatchEvent(new Event('input', { bubbles: true }));
        return {
          clientWidth: root.clientWidth,
          externalResources: resources.filter((resource) => new URL(resource).origin !== location.origin),
          fragmentErrors,
          horizontalOverflow: root.scrollWidth > root.clientWidth,
          innerHeight,
          innerWidth,
          interactive,
          reducedMotion: matchMedia('(prefers-reduced-motion: reduce)').matches,
          resourceCount: resources.length,
          scrollWidth: root.scrollWidth,
          storyboardCaption: document.querySelector('#story-caption').textContent.trim(),
          storyboardHeading: document.querySelector('#story-heading').textContent.trim(),
        };
      })()`,
      returnByValue: true,
    });
    if (evaluation.exceptionDetails) {
      throw new Error(`page evaluation failed: ${evaluation.exceptionDetails.text}`);
    }
    const facts = evaluation.result.value;
    const undersized = facts.interactive.filter(
      (item) => item.width < 44 || item.height < 44,
    );
    const errors = [];
    if (facts.innerWidth !== viewport.width || facts.clientWidth !== viewport.width) {
      errors.push(
        `viewport width mismatch: requested ${viewport.width}, inner/client ${facts.innerWidth}/${facts.clientWidth}`,
      );
    }
    if (facts.horizontalOverflow || facts.scrollWidth !== facts.clientWidth) {
      errors.push(`horizontal overflow: ${facts.scrollWidth} > ${facts.clientWidth}`);
    }
    if (undersized.length) {
      errors.push(`interactive targets below 44px: ${JSON.stringify(undersized)}`);
    }
    if (facts.externalResources.length) {
      errors.push(`external resources loaded: ${JSON.stringify(facts.externalResources)}`);
    }
    if (facts.fragmentErrors.length) {
      errors.push(`broken fragment links: ${facts.fragmentErrors.join(", ")}`);
    }
    if (!facts.reducedMotion) {
      errors.push("prefers-reduced-motion emulation was not observed by the page");
    }
    if (
      facts.storyboardHeading !== "11/11 只证明结构合同" ||
      !facts.storyboardCaption.startsWith("11/11 是固定闭集结构合同结果")
    ) {
      errors.push("draggable storyboard did not move to the 75 second subtitle cue");
    }

    async function capture(label) {
      const screenshot = await client.send("Page.captureScreenshot", {
        captureBeyondViewport: false,
        format: "png",
        fromSurface: true,
      });
      const screenshotPath = join(
        outputDirectory,
        `proofflow-public-demo-${viewport.label}-${label}.png`,
      );
      writeFileSync(screenshotPath, Buffer.from(screenshot.data, "base64"));
      return screenshotPath;
    }

    const screenshots = { top: await capture("top") };
    for (const [label, selector] of [
      ["proof", "#proof-path"],
      ["media", "#reference-media"],
    ]) {
      await client.send("Runtime.evaluate", {
        expression: `document.querySelector(${JSON.stringify(selector)}).scrollIntoView()`,
      });
      await client.send("Runtime.evaluate", {
        awaitPromise: true,
        expression:
          "new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve)))",
      });
      screenshots[label] = await capture(label);
    }
    return {
      clientWidth: facts.clientWidth,
      errors,
      externalResourceCount: facts.externalResources.length,
      horizontalOverflow: facts.horizontalOverflow,
      interactiveTargetCount: facts.interactive.length,
      minInteractiveHeight: Math.min(...facts.interactive.map((item) => item.height)),
      minInteractiveWidth: Math.min(...facts.interactive.map((item) => item.width)),
      reducedMotion: facts.reducedMotion,
      resourceCount: facts.resourceCount,
      screenshots,
      scrollWidth: facts.scrollWidth,
      storyboardCueAt75: facts.storyboardHeading,
      viewport: viewport.label,
    };
  } finally {
    client.close();
    await closeTarget(debuggingPort, target.id);
  }
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  mkdirSync(options.outputDirectory, { recursive: true });
  const profileDirectory = mkdtempSync(join(tmpdir(), "proofflow-public-demo-chrome-"));
  const browser = spawn(
    options.chrome,
    [
      "--headless=new",
      "--disable-background-networking",
      "--disable-component-update",
      "--disable-default-apps",
      "--disable-gpu",
      "--disable-sync",
      "--hide-scrollbars",
      "--metrics-recording-only",
      "--no-first-run",
      "--remote-debugging-port=0",
      `--user-data-dir=${profileDirectory}`,
      "about:blank",
    ],
    { stdio: ["ignore", "ignore", "pipe"] },
  );
  try {
    const webSocketUrl = await browserWebSocket(browser);
    const debuggingPort = Number(new URL(webSocketUrl).port);
    const results = [];
    for (const viewport of VIEWPORTS) {
      results.push(
        await inspectViewport({
          debuggingPort,
          outputDirectory: options.outputDirectory,
          url: options.url,
          viewport,
        }),
      );
    }
    const summary = {
      browser: basename(options.chrome),
      url: options.url,
      valid: results.every((result) => result.errors.length === 0),
      viewports: results,
    };
    writeFileSync(
      join(options.outputDirectory, "browser-qa-summary.json"),
      `${JSON.stringify(summary, null, 2)}\n`,
    );
    process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
    if (!summary.valid) {
      process.exitCode = 1;
    }
  } finally {
    browser.kill("SIGTERM");
    await new Promise((resolve) => setTimeout(resolve, 250));
    if (browser.exitCode === null) {
      browser.kill("SIGKILL");
    }
    rmSync(profileDirectory, { force: true, recursive: true });
  }
}

main().catch((error) => {
  process.stderr.write(`${error.stack || error.message}\n`);
  process.exitCode = 1;
});
