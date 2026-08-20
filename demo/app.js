(() => {
  "use strict";

  const elements = {
    approvalReason: document.querySelector("#approval-reason"),
    approveButton: document.querySelector("#approve-button"),
    benchmarkButton: document.querySelector("#benchmark-button"),
    benchmarkResults: document.querySelector("#benchmark-results"),
    benchmarkScore: document.querySelector("#benchmark-score"),
    calculationTotal: document.querySelector("#calculation-total"),
    evidenceCount: document.querySelector("#evidence-count"),
    fixturePin: document.querySelector("#fixture-pin"),
    packageButton: document.querySelector("#package-button"),
    packageFiles: document.querySelector("#package-files"),
    prepareButton: document.querySelector("#prepare-button"),
    probeButton: document.querySelector("#probe-button"),
    responseCode: document.querySelector("#response-code"),
    responseMessage: document.querySelector("#response-message"),
    responseStrip: document.querySelector("#response-strip"),
    ruleCount: document.querySelector("#rule-count"),
    rulePin: document.querySelector("#rule-pin"),
    stageValue: document.querySelector("#stage-value"),
    subjectHash: document.querySelector("#subject-hash"),
    traceList: document.querySelector("#trace-list"),
    verifyButton: document.querySelector("#verify-button"),
  };

  let requestToken = "";
  let busy = false;
  let currentState = null;

  function setResponse(kind, code, message) {
    elements.responseStrip.classList.remove("is-error", "is-success");
    if (kind) {
      elements.responseStrip.classList.add(kind);
    }
    elements.responseCode.textContent = code;
    elements.responseMessage.textContent = message;
  }

  function setChainClass(step, className, label) {
    const item = document.querySelector(`[data-step="${step}"]`);
    const output = document.querySelector(`#step-${step}`);
    item.classList.remove("is-active", "is-blocked", "is-complete", "is-verified");
    if (className) {
      item.classList.add(className);
    }
    output.textContent = label;
  }

  function renderTrace(events) {
    elements.traceList.replaceChildren();
    if (!events.length) {
      const item = document.createElement("li");
      ["000", "SYSTEM", "WAITING_FOR_PREPARE", "LOCAL"].forEach((value, index) => {
        const node = document.createElement(index === 1 ? "b" : index === 3 ? "em" : "span");
        node.textContent = value;
        if (index === 0) {
          node.className = "mono";
        }
        item.append(node);
      });
      elements.traceList.append(item);
      return;
    }
    events.slice(-18).forEach((event) => {
      const item = document.createElement("li");
      const sequence = document.createElement("span");
      const actor = document.createElement("b");
      const type = document.createElement("span");
      const status = document.createElement("em");
      sequence.className = "mono";
      sequence.textContent = String(event.sequence).padStart(3, "0");
      actor.textContent = event.actor || "—";
      type.textContent = event.event || "—";
      status.textContent = event.status || "—";
      item.append(sequence, actor, type, status);
      elements.traceList.append(item);
    });
    elements.traceList.scrollTop = elements.traceList.scrollHeight;
  }

  function renderBenchmark(benchmark) {
    if (!benchmark) {
      elements.benchmarkScore.textContent = "—/11";
      return;
    }
    elements.benchmarkScore.textContent = benchmark.contract_pass_fraction;
    elements.benchmarkResults.replaceChildren();
    benchmark.results.forEach((result) => {
      const item = document.createElement("li");
      const title = document.createElement("span");
      const status = document.createElement("b");
      title.textContent = `${result.id} / ${result.fault}`;
      status.textContent = result.passed ? "PASS" : "FAIL";
      if (!result.passed) {
        item.className = "is-failed";
      }
      item.title = result.title || result.id;
      item.append(title, status);
      elements.benchmarkResults.append(item);
    });
  }

  function renderState(state) {
    currentState = state;
    const stage = state.run.stage;
    const prepared = stage !== "NOT_PREPARED";
    const awaiting = stage === "AWAITING_APPROVAL";
    const approved = stage === "APPROVED";
    const packaged = stage === "PACKAGED";
    const verified = packaged && state.verification && state.verification.valid;
    const verificationFailed =
      packaged && state.verification && state.verification.valid === false;

    elements.stageValue.textContent = stage;
    elements.evidenceCount.textContent = String(state.artifacts.evidence);
    elements.ruleCount.textContent = String(state.artifacts.rules);
    elements.calculationTotal.textContent = state.artifacts.calculation_total_cny || "—";
    elements.packageFiles.textContent = String(state.artifacts.package_files);
    elements.subjectHash.textContent = state.run.subject_hash || "not prepared";
    elements.fixturePin.textContent = `fixture / ${state.pins.fixture_bundle}`;
    elements.rulePin.textContent = `rules / ${state.pins.rule_catalog}`;

    elements.prepareButton.disabled = busy || prepared;
    elements.probeButton.disabled = busy || !awaiting || state.gate_probe === "BLOCKED_AS_EXPECTED";
    elements.approvalReason.disabled = busy || !awaiting;
    elements.approveButton.disabled = busy || !awaiting;
    elements.packageButton.disabled = busy || !approved;
    elements.verifyButton.disabled = busy || !packaged;
    elements.benchmarkButton.disabled = busy;

    setChainClass("prepare", prepared ? "is-complete" : "is-active", prepared ? "SEALED" : "READY");
    setChainClass(
      "gate",
      state.gate_probe === "BLOCKED_AS_EXPECTED" ? "is-blocked" : awaiting ? "is-active" : prepared ? "is-complete" : "",
      state.gate_probe === "BLOCKED_AS_EXPECTED" ? "409 BLOCKED" : awaiting ? "WAITING" : prepared ? "PASSED" : "LOCKED",
    );
    setChainClass("approve", approved || packaged ? "is-complete" : awaiting ? "is-active" : "", approved || packaged ? "LOCAL_DEMO" : awaiting ? "REASON" : "WAIT");
    setChainClass("package", packaged ? "is-complete" : approved ? "is-active" : "", packaged ? "SEALED" : approved ? "READY" : "WAIT");
    setChainClass(
      "verify",
      verified ? "is-verified" : verificationFailed ? "is-blocked" : packaged ? "is-active" : "",
      verified
        ? "VALID"
        : verificationFailed
          ? `FAILED / ${state.verification.errors.length}`
          : packaged
            ? "READY"
            : "WAIT",
    );
    renderTrace(state.trace);
    renderBenchmark(state.benchmark);
  }

  function setBusy(value) {
    busy = value;
    document.body.classList.toggle("is-loading", busy);
    document.querySelectorAll("button, textarea").forEach((control) => {
      if (busy) {
        control.setAttribute("aria-busy", "true");
      } else {
        control.removeAttribute("aria-busy");
      }
    });
    if (currentState) {
      renderState(currentState);
    }
  }

  async function callAction(action) {
    if (busy) {
      return;
    }
    setBusy(true);
    setResponse("", `RUNNING / ${action.toUpperCase()}`, "本地确定性动作执行中…");
    const payload = action === "approve" ? { reason: elements.approvalReason.value } : {};
    try {
      const response = await fetch(`/api/${action}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-ProofFlow-Request-Token": requestToken,
        },
        body: JSON.stringify(payload),
        credentials: "same-origin",
      });
      const data = await response.json();
      if (data.state) {
        renderState(data.state);
      }
      if (!response.ok) {
        const expectedGate = data.error && data.error.code === "HUMAN_GATE_REQUIRED";
        setResponse(
          "is-error",
          `${response.status} / ${data.error.code}`,
          expectedGate ? `${data.error.message} 这是预期的 fail-closed 证据。` : data.error.message,
        );
        return;
      }
      const successMessage = {
        approve: "人工理由已记录；approval_method=LOCAL_DEMO，且绑定当前 subject hash。",
        benchmark: `${data.result.contract_pass_fraction} 场景通过；benchmark 临时目录已清理。`,
        package: "评审包已生成；外部副作用仍为 false。",
        prepare: "公开合成证据链已准备，并在 AWAITING_APPROVAL 停止。",
        reset: "前一运行临时目录已清理；控制台已回到初始状态。",
        verify: `校验完成：${data.result.checked_artifacts} 个 artifact，${data.result.checked_package_files} 个 package file。`,
      }[action];
      setResponse("is-success", `200 / ${action.toUpperCase()}`, successMessage);
    } catch (_error) {
      setResponse("is-error", "LOCAL / CONNECTION_ERROR", "本地服务不可达或响应不是有效 JSON；未执行后续动作。");
    } finally {
      setBusy(false);
    }
  }

  async function bootstrap() {
    setBusy(true);
    try {
      const response = await fetch("/api/bootstrap", { credentials: "same-origin" });
      const data = await response.json();
      if (!response.ok) {
        throw new Error("bootstrap rejected");
      }
      requestToken = data.request_token;
      renderState(data.state);
      setResponse("", "LOCAL / READY", "固定输入 pin 已核验；等待显式用户动作。");
    } catch (_error) {
      setResponse("is-error", "LOCAL / BOOTSTRAP_FAILED", "无法初始化本地控制台；所有动作保持禁用。");
    } finally {
      setBusy(false);
    }
  }

  document.querySelectorAll("button[data-action]").forEach((button) => {
    button.addEventListener("click", () => callAction(button.dataset.action));
  });

  bootstrap();
})();
