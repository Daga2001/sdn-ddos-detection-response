/**
 * The Detection tab: choose the detector (an LLM or entropy) and tune it. The values
 * live in the experiment, so they are saved with every run and come back on replay.
 */
import type { ReactNode } from "react";
import { CheckField, Field, Hint } from "./Field";
import {
  defaultDetection,
  defaultEntropy,
  defaultResponse,
  detectionFromService,
  knownModels,
} from "./types";
import type {
  DetectionConfig,
  DetectionMode,
  DetectionOptions,
  EntropyFeature,
  EntropyMeasure,
  EntropyParams,
  Experiment,
  ResponseParams,
  ThresholdCenter,
} from "./types";

const modes: { id: DetectionMode; label: string; note: string }[] = [
  {
    id: "llm",
    label: "LLM",
    note: "A language model judges each flow. Fast to react, but a slow model can hold up the controller.",
  },
  {
    id: "entropy",
    label: "Entropy",
    note: "Statistics of who talks to whom. No model needed; it must first learn what is normal.",
  },
  {
    id: "off",
    label: "No detection",
    note: "Only measure the attack. Nothing is judged and no response is applied.",
  },
];

const entropyMeasures: Record<EntropyMeasure, string> = {
  shannon: "Shannon",
  renyi: "Rényi",
  tsallis: "Tsallis",
  norm: "Normalised Shannon",
  min: "Min-entropy",
};

function NumberField({
  label,
  hint,
  value,
  onChange,
  min,
  max,
  step,
  disabled,
}: {
  label: string;
  hint: string;
  value: number;
  onChange: (value: number) => void;
  min: number;
  max: number;
  step?: number;
  disabled: boolean;
}) {
  return (
    <Field label={label} hint={hint}>
      <input
        type="number"
        value={Number.isFinite(value) ? value : ""}
        min={min}
        max={max}
        step={step ?? 1}
        disabled={disabled}
        onChange={(event) => {
          const next = event.target.valueAsNumber;
          if (Number.isFinite(next)) onChange(next);
        }}
      />
    </Field>
  );
}

function Section({
  title,
  hint,
  children,
}: {
  title: string;
  hint: string;
  children: ReactNode;
}) {
  return (
    <section className="config-section">
      <h3>
        {title}
        <Hint text={hint} />
      </h3>
      {children}
    </section>
  );
}

/**
 * Seconds of baseline the entropy detector needs to learn what is normal. Only windows
 * with traffic count and a short window is often quiet, so a window is taken as lasting
 * at least 2.5 s here (a 1 s window needed ~2.5 s of baseline per usable window in the lab).
 */
export function entropyWarmupSeconds(entropy: EntropyParams): number {
  return entropy.warmup_windows * Math.max(entropy.window_seconds, 2.5);
}

export function DetectionPanel({
  experiment,
  setExperiment,
  options,
  locked,
  readOnly,
  reload,
}: {
  experiment: Experiment;
  setExperiment: (value: Experiment) => void;
  options: DetectionOptions;
  locked: boolean;
  readOnly: boolean;
  reload: () => void;
}) {
  const config = experiment.detection;
  const disabled = locked || readOnly;
  const set = (change: Partial<DetectionConfig>) =>
    config &&
    setExperiment({ ...experiment, detection: { ...config, ...change } });
  const setEntropy = (change: Partial<EntropyParams>) =>
    config && set({ entropy: { ...config.entropy, ...change } });
  const setResponse = (change: Partial<ResponseParams>) =>
    config && set({ response: { ...config.response, ...change } });

  if (!config)
    return (
      <div className="panel-content">
        <span className="eyebrow">DETECTION / 01</span>
        <h2>Choose how attacks are detected.</h2>
        {options.available === false ? (
          <p className="notice warning inline">
            <strong>This lab has no detector service to configure.</strong>
            <span>{options.reason}</span>
            <small>
              Start the lab with <code>docker compose up</code> to pick an LLM
              or entropy from here.
            </small>
          </p>
        ) : (
          <p>Reading the detector service…</p>
        )}
        <button onClick={reload} disabled={locked}>
          Check again
        </button>
      </div>
    );

  const installed = options.models ?? [];
  const modelNames = installed.length
    ? installed
    : knownModels.map((item) => item.name);
  const choices = modelNames.includes(config.model)
    ? modelNames
    : [config.model, ...modelNames];
  const missing = installed.length > 0 && !installed.includes(config.model);
  const note = knownModels.find((item) => item.name === config.model)?.note;
  const response = config.response;
  const warmup = entropyWarmupSeconds(config.entropy);
  const realRules = experiment.mitigation && !response.dry_run;

  return (
    <div className="panel-content detection-panel">
      <span className="eyebrow">DETECTION / 01</span>
      <h2>Choose how attacks are detected.</h2>
      <p>
        This setup is saved with every run you start, so a replay or an exported
        record shows exactly what judged it.
      </p>
      {readOnly && (
        <p className="role-empty">
          Showing the setup recorded with this replay. It cannot be edited here.
        </p>
      )}
      {options.available === false && !readOnly && (
        <p className="role-empty warn">
          {options.reason ?? "The detector service is not reachable."} A run
          that asks for a detector will be refused until it is back.
        </p>
      )}

      <div className="mode-cards" role="group" aria-label="Detection type">
        {modes.map((mode) => (
          <button
            key={mode.id}
            type="button"
            className={config.mode === mode.id ? "active" : ""}
            aria-pressed={config.mode === mode.id}
            disabled={disabled}
            title={mode.note}
            onClick={() =>
              setExperiment({
                ...experiment,
                mitigation: mode.id === "off" ? false : experiment.mitigation,
                detection: { ...config, mode: mode.id },
              })
            }
          >
            <strong>{mode.label}</strong>
            <small>{mode.note}</small>
          </button>
        ))}
      </div>

      {config.mode === "llm" && (
        <Section
          title="LLM detector"
          hint="The language model reads each flow's rate and size and answers attack or normal. The setup was calibrated on this lab's own traffic."
        >
          <Field
            label="Model"
            hint="Which Ollama model judges each flow. Smaller models answer faster; the slower the model, the longer the controller waits per verdict."
          >
            <select
              value={config.model}
              disabled={disabled}
              onChange={(event) => set({ model: event.target.value })}
            >
              {choices.map((name) => (
                <option key={name} value={name}>
                  {name}
                </option>
              ))}
            </select>
          </Field>
          {note && <p className="field-note">{note}</p>}
          {missing && (
            <p className="role-empty warn">
              {config.model} is not installed in Ollama, so the run would be
              refused. Install it on the host first.
            </p>
          )}
          <Field
            label="Prompt profile"
            hint="lab: thresholds taken from this lab's own traffic (recommended). insdn: calibrated on the InSDN dataset; it misses this lab's floods."
          >
            <select
              value={config.prompt}
              disabled={disabled}
              onChange={(event) =>
                set({ prompt: event.target.value as "insdn" | "lab" })
              }
            >
              <option value="lab">lab (this lab's traffic)</option>
              <option value="insdn">insdn (dataset)</option>
            </select>
          </Field>
          <div className="field-pair">
            <NumberField
              label="Samples per poll"
              hint="How many flows the controller sends to the model each time it polls a switch. Fewer is lighter: with a slow model the controller can spend most of its time waiting and stop serving legitimate clients. 1 to 50."
              value={config.llm_max_samples}
              min={1}
              max={50}
              disabled={disabled}
              onChange={(value) => set({ llm_max_samples: value })}
            />
            <NumberField
              label="Attack probability ≥"
              hint="A flow counts as an attack when the model's probability reaches this value. 0 to 1."
              value={config.threshold}
              min={0}
              max={1}
              step={0.05}
              disabled={disabled}
              onChange={(value) => set({ threshold: value })}
            />
          </div>
        </Section>
      )}

      {config.mode === "entropy" && (
        <Section
          title="Entropy detector"
          hint="Every window it measures how spread out the sources and destinations of traffic are, learns the normal band, and alarms when the traffic leaves it for enough windows in a row."
        >
          {experiment.baseline < warmup + 40 && (
            <p className="role-empty warn">
              It needs about {warmup} s of baseline to learn what is normal
              (warm-up windows × window length), plus about 30 s because the
              first window waits for every switch and quiet windows do not
              count. This run has {experiment.baseline} s. Raise the baseline to
              at least {warmup + 40} s in the Experiment tab or the flood may
              start while it is still learning and go unnoticed.
            </p>
          )}
          <div className="preset-row" role="group" aria-label="Entropy presets">
            <span>Presets</span>
            <button
              type="button"
              disabled={disabled}
              title="The calibrated defaults: 5 s windows and polls, Shannon entropy, EWMA band. Reacts in ~10 s."
              onClick={() =>
                set({
                  poll_seconds: defaultDetection.poll_seconds,
                  entropy: defaultEntropy,
                })
              }
            >
              Original
            </button>
            <button
              type="button"
              disabled={disabled}
              title="1 s windows, polls every 0.5 s, normalised Shannon entropy, 30 warm-up windows, forwarding rules without the port. In the university lab it named and blocked three attackers 1.7 s into a SYN flood and the service never stopped answering."
              onClick={() =>
                set({
                  poll_seconds: 0.5,
                  entropy: {
                    ...config.entropy,
                    window_seconds: 1,
                    warmup_windows: 30,
                    consecutive_windows: 2,
                    measure: "norm",
                    match_ports: false,
                  },
                })
              }
            >
              Fast reaction
            </button>
            <button
              type="button"
              disabled={disabled}
              title="Normalised entropy of the destination addresses in 1 s windows. The alarm threshold is an EWMA of that entropy (weight 0.13) minus a margin of 0.01, and it is not updated while an alarm lasts. One window raises the alarm. From Ding, Savi and Siracusa (IEEE TDSC 2022); the fast-reaction timing, 30 warm-up windows and port-free rules are this lab's."
              onClick={() =>
                set({
                  poll_seconds: 0.5,
                  entropy: {
                    ...config.entropy,
                    window_seconds: 1,
                    warmup_windows: 30,
                    consecutive_windows: 1,
                    measure: "norm",
                    center: "ewma_margin",
                    alpha: 0.13,
                    margin: 0.01,
                    watch_pairs: false,
                    decide: ["dst"],
                    context: "normal",
                    match_ports: false,
                  },
                })
              }
            >
              Destination entropy
            </button>
            <button
              type="button"
              disabled={disabled}
              title="Normalised entropy of the (source, destination) pairs in 1 s windows. The alarm threshold comes from a second-order EWMA of the entropy (weight 0.1): its trend minus 4 times its volatility, not updated while an alarm lasts and never falling more than 10 % per window. One window raises the alarm. From Zhang et al. (WF-IoT 2026), spatial part; the fast-reaction timing, 30 warm-up windows and port-free rules are this lab's."
              onClick={() =>
                set({
                  poll_seconds: 0.5,
                  entropy: {
                    ...config.entropy,
                    window_seconds: 1,
                    warmup_windows: 30,
                    consecutive_windows: 1,
                    measure: "norm",
                    center: "ewma2",
                    alpha: 0.1,
                    k: 4,
                    watch_pairs: true,
                    decide: ["pair"],
                    context: "normal",
                    match_ports: false,
                  },
                })
              }
            >
              Pair entropy
            </button>
          </div>
          <div className="field-pair">
            <NumberField
              label="Window · seconds"
              hint="Length of each measurement window. Shorter reacts faster but is noisier. 1 to 60."
              value={config.entropy.window_seconds}
              min={1}
              max={60}
              disabled={disabled}
              onChange={(value) => setEntropy({ window_seconds: value })}
            />
            <Field
              label="Window mode"
              hint="mean: average the traffic of every poll inside the window (recommended, less noise). snapshot: only the last poll."
            >
              <select
                value={config.entropy.window_mode}
                disabled={disabled}
                onChange={(event) =>
                  setEntropy({
                    window_mode: event.target.value as "snapshot" | "mean",
                  })
                }
              >
                <option value="mean">mean</option>
                <option value="snapshot">snapshot</option>
              </select>
            </Field>
          </div>
          <div className="field-pair">
            <NumberField
              label="Band width · k"
              hint="How many standard deviations (or MADs) around the learned normal still count as normal. Smaller catches more but raises false alarms; larger is calmer but can miss a flood. 0.5 to 10."
              value={config.entropy.k}
              min={0.5}
              max={10}
              step={0.1}
              disabled={disabled}
              onChange={(value) => setEntropy({ k: value })}
            />
            <NumberField
              label="Warm-up windows"
              hint="Windows used to learn what is normal before it may alarm. More is steadier but needs a longer baseline. 1 to 120."
              value={config.entropy.warmup_windows}
              min={1}
              max={120}
              disabled={disabled}
              onChange={(value) => setEntropy({ warmup_windows: value })}
            />
          </div>
          <div className="field-pair">
            <NumberField
              label="Consecutive windows"
              hint="Windows in a row outside the band before the alarm is confirmed. More avoids one-off blips but delays detection. 1 to 20."
              value={config.entropy.consecutive_windows}
              min={1}
              max={20}
              disabled={disabled}
              onChange={(value) => setEntropy({ consecutive_windows: value })}
            />
            <NumberField
              label="Minimum rate · pkt/s"
              hint="A window quieter than this is ignored (the network is idle). Lower it for a very quiet network."
              value={config.entropy.min_rate}
              min={0}
              max={100000}
              step={0.5}
              disabled={disabled}
              onChange={(value) => setEntropy({ min_rate: value })}
            />
          </div>
          <h4 className="subsection">
            Measure and threshold
            <Hint text="Which entropy is computed and how the normal band around it is learned. The defaults are the original detector: Shannon entropy and an exponentially weighted mean." />
          </h4>
          <div className="field-pair">
            <Field
              label="Entropy measure"
              hint="Shannon: the classic one. Rényi: its order tunes how much the busiest source weighs (higher means more); Yu et al. (2024) found an order near 10 best on their datasets. Tsallis: a polynomial cousin. Normalised Shannon: scaled to 0–1 so it does not depend on how many hosts talk. Min-entropy: only the largest share counts."
            >
              <select
                value={config.entropy.measure}
                disabled={disabled}
                onChange={(event) =>
                  setEntropy({ measure: event.target.value as EntropyMeasure })
                }
              >
                {Object.entries(entropyMeasures).map(([measure, name]) => (
                  <option key={measure} value={measure}>
                    {name}
                  </option>
                ))}
              </select>
            </Field>
            {(config.entropy.measure === "renyi" ||
              config.entropy.measure === "tsallis") && (
              <NumberField
                label="Order"
                hint="Order α of Rényi (q of Tsallis). 1 is Shannon; higher values look more at the busiest value. 0.1 to 64."
                value={config.entropy.order}
                min={0.1}
                max={64}
                step={0.5}
                disabled={disabled}
                onChange={(value) => setEntropy({ order: value })}
              />
            )}
          </div>
          <div className="field-pair">
            <Field
              label="Threshold centre"
              hint="How the normal level is learned. EWMA mean: exponentially weighted mean (the original detector). Rolling mean and rolling median: the mean or the median of the last windows; the median shrugs off up to half of the windows being abnormal, so it is the one to pair with “Every window”. Improved EWMA: the model of Yu et al. (2024). EWMA minus a margin: the threshold is an EWMA of the entropy minus a fixed margin. Second-order EWMA: an EWMA of the entropy and of its square, minus kappa times their volatility; it never falls more than 10 % per window."
            >
              <select
                value={config.entropy.center}
                disabled={disabled}
                onChange={(event) =>
                  setEntropy({ center: event.target.value as ThresholdCenter })
                }
              >
                <option value="ewma">EWMA mean (original)</option>
                <option value="mean">Rolling mean</option>
                <option value="median">Rolling median</option>
                <option value="yu">Improved EWMA (Yu et al.)</option>
                <option value="ewma_margin">EWMA minus a margin</option>
                <option value="ewma2">Second-order EWMA</option>
              </select>
            </Field>
            <Field
              label="Spread"
              hint="How far normal windows scatter around the centre: the standard deviation, or the median absolute deviation (MAD), which a few abnormal windows cannot inflate. Only for the rolling mean and median."
            >
              <select
                value={config.entropy.spread}
                disabled={
                  disabled ||
                  (config.entropy.center !== "mean" &&
                    config.entropy.center !== "median")
                }
                onChange={(event) =>
                  setEntropy({ spread: event.target.value as "std" | "mad" })
                }
              >
                <option value="std">Standard deviation</option>
                <option value="mad">MAD (robust)</option>
              </select>
            </Field>
          </div>
          <div className="field-pair">
            <NumberField
              label="History · windows"
              hint="How many past windows the rolling mean, median and improved EWMA remember. 0 means every window since the run started: the whole run, not only the baseline (the improved EWMA then uses 15). A smaller number adapts faster."
              value={config.entropy.history}
              min={0}
              max={1000}
              disabled={disabled || config.entropy.center === "ewma"}
              onChange={(value) => setEntropy({ history: value })}
            />
            <Field
              label="Learn from"
              hint="Normal-looking windows only: the band is frozen while a window is suspicious, so a flood cannot move it. Every window: the band uses the whole run's context, attack included; pair it with the median so the flood does not drag the centre."
            >
              <select
                value={config.entropy.context}
                disabled={disabled}
                onChange={(event) =>
                  setEntropy({
                    context: event.target.value as "normal" | "all",
                  })
                }
              >
                <option value="normal">Normal-looking windows</option>
                <option value="all">Every window (full context)</option>
              </select>
            </Field>
          </div>
          {config.entropy.center === "ewma_margin" && (
            <NumberField
              label="Margin"
              hint="The threshold is the EWMA of the entropy minus this margin (0.01 by default). Larger is calmer: its authors report no false alarms above about 0.04 at the price of some missed attacks. 0 to 1. The smoothing is the 'Smoothing · alpha' of the advanced settings (0.13 in the paper)."
              value={config.entropy.margin}
              min={0}
              max={1}
              step={0.01}
              disabled={disabled}
              onChange={(value) => setEntropy({ margin: value })}
            />
          )}
          {config.entropy.center === "ewma2" && (
            <NumberField
              label="No-decrease rate · pkt/s"
              hint="With traffic above this packet rate the threshold cannot decrease, so a flood cannot lower it (800 by default); below it the threshold falls by at most 10 % per window. Band width k is kappa (4) and the 'Smoothing · alpha' of the advanced settings is beta (0.1)."
              value={config.entropy.rate_threshold}
              min={0}
              max={1000000}
              step={50}
              disabled={disabled}
              onChange={(value) => setEntropy({ rate_threshold: value })}
            />
          )}
          <CheckField
            disabled={disabled}
            label="Also watch destination ports"
            hint="Adds the entropy of the destination ports. A SYN flood makes every reply a flow to a different port, so this entropy jumps."
            checked={config.entropy.watch_ports}
            onChange={(on) => !disabled && setEntropy({ watch_ports: on })}
          />
          <CheckField
            disabled={disabled}
            label="Also watch protocols"
            hint="Adds the entropy of the protocols (TCP, UDP, ICMP). It changes when a flood uses a protocol the network rarely carries."
            checked={config.entropy.watch_protocols}
            onChange={(on) => !disabled && setEntropy({ watch_protocols: on })}
          />
          <CheckField
            disabled={disabled}
            label="Also watch source–destination pairs"
            hint="Adds the entropy of the (source, destination) pairs, the distribution the pair-entropy preset decides on. A flood from a few hosts to one victim concentrates it."
            checked={config.entropy.watch_pairs}
            onChange={(on) =>
              !disabled &&
              setEntropy({
                watch_pairs: on,
                decide: on
                  ? config.entropy.decide
                  : config.entropy.decide.filter((name) => name !== "pair"),
              })
            }
          />
          <Field
            label="Alarm decided by"
            hint="Which distributions may raise an alarm. All: any watched entropy leaving its band (the original detector). Destinations only: what the destination-entropy preset uses. Pairs only: what the pair-entropy preset uses. The other entropies are still shown."
          >
            <select
              value={
                config.entropy.decide.length === 0
                  ? "all"
                  : config.entropy.decide.join("+")
              }
              disabled={disabled}
              onChange={(event) => {
                const value = event.target.value;
                setEntropy({
                  decide:
                    value === "all"
                      ? []
                      : (value.split("+") as EntropyFeature[]),
                  watch_pairs:
                    value === "pair" ? true : config.entropy.watch_pairs,
                });
              }}
            >
              <option value="all">All the watched distributions</option>
              <option value="dst">Destinations only</option>
              <option value="pair">Source–destination pairs only</option>
              {config.entropy.decide.length > 0 &&
                !["dst", "pair"].includes(config.entropy.decide.join("+")) && (
                  <option value={config.entropy.decide.join("+")}>
                    {config.entropy.decide.join(" + ")}
                  </option>
                )}
            </select>
          </Field>
          <CheckField
            disabled={disabled}
            label="Match ports in forwarding rules"
            hint="On (the original behaviour): every reply of a SYN flood goes to another source port, so each one becomes a flow of its own, a rule and a packet to the controller; thousands per second saturate it and the victim's service stops answering. Off: a rule covers a source, a destination and a protocol, so the flood adds no rules after its first packet and the controller keeps up. The detector sees the same IPs either way."
            checked={config.entropy.match_ports}
            onChange={(on) => !disabled && setEntropy({ match_ports: on })}
          />
          <details className="advanced">
            <summary>Advanced entropy settings</summary>
            <div className="field-pair">
              <NumberField
                label="Smoothing · alpha"
                hint="How fast the EWMA band follows the traffic while learning. 0 to 1. The EWMA mean and the two published thresholds use it (0.13 in the destination-entropy preset, 0.1 in the pair-entropy one)."
                value={config.entropy.alpha}
                min={0.01}
                max={1}
                step={0.05}
                disabled={
                  disabled ||
                  !["ewma", "ewma_margin", "ewma2"].includes(
                    config.entropy.center,
                  )
                }
                onChange={(value) => setEntropy({ alpha: value })}
              />
              <NumberField
                label="Minimum deviation"
                hint="Floor of the band's standard deviation, so a perfectly steady baseline does not make the band zero wide."
                value={config.entropy.min_std}
                min={0}
                max={10}
                step={0.01}
                disabled={disabled}
                onChange={(value) => setEntropy({ min_std: value })}
              />
            </div>
            <div className="field-pair">
              <NumberField
                label="Candidate share"
                hint="A source must carry at least this share of the traffic to be named an attacker. 0 to 1."
                value={config.entropy.candidate_share}
                min={0}
                max={1}
                step={0.05}
                disabled={disabled}
                onChange={(value) => setEntropy({ candidate_share: value })}
              />
              <NumberField
                label="Candidate rate · pkt/s"
                hint="A source must also send at least this much to be named, so an ordinary host is never blamed during a quiet window."
                value={config.entropy.candidate_min_rate}
                min={0}
                max={100000}
                disabled={disabled}
                onChange={(value) => setEntropy({ candidate_min_rate: value })}
              />
            </div>
            <NumberField
              label="Hold windows before learning"
              hint="A normal-looking window waits this many windows before it updates the band, and is discarded if the next ones are suspicious. It keeps the start of a flood out of the baseline. 0 turns it off."
              value={config.entropy.update_hold}
              min={0}
              max={20}
              disabled={disabled}
              onChange={(value) => setEntropy({ update_hold: value })}
            />
            <CheckField
              disabled={disabled || config.entropy.center !== "ewma"}
              label="Slower smoothing after warm-up"
              hint="Makes the EWMA band follow the traffic more slowly once the warm-up is over, so a flood cannot drag it along."
              checked={config.entropy.alpha_run !== null}
              onChange={(on) =>
                !disabled && setEntropy({ alpha_run: on ? 0.05 : null })
              }
            />
            {config.entropy.alpha_run !== null && (
              <NumberField
                label="Smoothing after warm-up"
                hint="The smoothing used once the warm-up is over. 0 to 1."
                value={config.entropy.alpha_run}
                min={0.01}
                max={1}
                step={0.01}
                disabled={disabled}
                onChange={(value) => setEntropy({ alpha_run: value })}
              />
            )}
            <CheckField
              disabled={disabled}
              label="Count a flow once across switches"
              hint="Off by default: with this lab's quiet baseline it lowers the traffic under the minimum rate, windows are skipped and the warm-up takes longer."
              checked={config.entropy.dedupe_switches}
              onChange={(on) =>
                !disabled && setEntropy({ dedupe_switches: on })
              }
            />
          </details>
        </Section>
      )}

      {config.mode !== "off" && (
        <Section
          title="Reaction speed"
          hint="Both detectors work from the switches' flow statistics, so how often the controller asks for them is how soon a flood can be seen."
        >
          <NumberField
            label="Poll every · s"
            hint="Seconds between statistics requests to each switch. Lower reacts sooner (a flood is usually seen after two polls) but loads the controller more. 0.5 to 60; the lab default is 5."
            value={config.poll_seconds}
            min={0.5}
            max={60}
            step={0.5}
            disabled={disabled}
            onChange={(value) => set({ poll_seconds: value })}
          />
        </Section>
      )}

      {config.mode !== "off" && (
        <Section
          title="Response"
          hint="What the controller does when the detector names an attacker. Off unless you turn it on, and a simulation by default."
        >
          <CheckField
            disabled={disabled}
            label="Apply a response to detected attackers"
            hint="Without this the detector only watches and records. With it, the controller reacts to the sources it names."
            checked={experiment.mitigation}
            onChange={(on) =>
              !disabled && setExperiment({ ...experiment, mitigation: on })
            }
          />
          {experiment.mitigation && (
            <>
              <Field
                label="Policy"
                hint="block: drop all the source's traffic. rate_limit: let it through at a capped rate. escalate: limit first, then block if it keeps sending far above the cap."
              >
                <select
                  value={response.policy}
                  disabled={disabled}
                  onChange={(event) =>
                    setResponse({
                      policy: event.target.value as ResponseParams["policy"],
                    })
                  }
                >
                  <option value="block">block</option>
                  <option value="rate_limit">rate_limit</option>
                  <option value="escalate">escalate (limit, then block)</option>
                </select>
              </Field>
              <CheckField
                disabled={disabled}
                label="Simulation only (dry run)"
                hint="Records what it would do without touching the switches. Turn it off to install the rules for real, inside this emulated lab."
                checked={response.dry_run}
                onChange={(on) => !disabled && setResponse({ dry_run: on })}
              />
              {realRules ? (
                <p className="notice warning inline" role="status">
                  <strong>Real rules will be installed.</strong>
                  <span>
                    The controller will block or limit the sources the detector
                    names, in this emulated lab's switches. A false alarm
                    affects a legitimate client.
                  </span>
                </p>
              ) : (
                <p className="field-note">
                  Simulation: the decisions are recorded but the switches are
                  not changed.
                </p>
              )}
              {response.policy !== "block" && (
                <div className="field-pair">
                  <NumberField
                    label="Cap · pkt/s"
                    hint="Rate a limited source is allowed to keep. 1 to 1,000,000."
                    value={response.rate_limit_pps}
                    min={1}
                    max={1000000}
                    disabled={disabled}
                    onChange={(value) => setResponse({ rate_limit_pps: value })}
                  />
                  <NumberField
                    label="Limit lasts · s"
                    hint="How long the cap stays in place. 1 to 3600."
                    value={response.rate_limit_seconds}
                    min={1}
                    max={3600}
                    disabled={disabled}
                    onChange={(value) =>
                      setResponse({ rate_limit_seconds: value })
                    }
                  />
                </div>
              )}
              <div className="field-pair">
                {response.policy === "escalate" && (
                  <NumberField
                    label="Escalate after · s"
                    hint="With escalate: how long a source must keep sending far above the cap before it is blocked. 0 to 3600."
                    value={response.escalate_after_seconds}
                    min={0}
                    max={3600}
                    disabled={disabled}
                    onChange={(value) =>
                      setResponse({ escalate_after_seconds: value })
                    }
                  />
                )}
                {response.policy !== "rate_limit" && (
                  <NumberField
                    label="Block lasts · s"
                    hint="How long a blocked source stays blocked. 1 to 86400."
                    value={response.block_seconds}
                    min={1}
                    max={86400}
                    disabled={disabled}
                    onChange={(value) => setResponse({ block_seconds: value })}
                  />
                )}
              </div>
              <div className="field-pair">
                <NumberField
                  label="Detections needed"
                  hint="Act on a source only after it was flagged this many times, in different polls. 1 acts on the first detection; 2 ignores a one-off false alarm on a quiet legitimate client (a flood is flagged poll after poll) at the cost of one more poll before the response. 1 to 10."
                  value={response.confirm_hits}
                  min={1}
                  max={10}
                  disabled={disabled}
                  onChange={(value) => setResponse({ confirm_hits: value })}
                />
                {response.confirm_hits > 1 && (
                  <NumberField
                    label="Within · s"
                    hint="The detections must fall inside this window. 1 to 600."
                    value={response.confirm_seconds}
                    min={1}
                    max={600}
                    disabled={disabled}
                    onChange={(value) =>
                      setResponse({ confirm_seconds: value })
                    }
                  />
                )}
              </div>
              <Field
                label="Never act on · addresses"
                hint="Comma-separated private addresses or networks the response must never touch, such as 10.0.0.1 or 10.0.0.0/30."
              >
                <input
                  type="text"
                  value={response.protected.join(", ")}
                  placeholder="e.g. 10.0.0.1, 10.0.0.0/30"
                  disabled={disabled}
                  onChange={(event) =>
                    setResponse({
                      protected: event.target.value
                        .split(",")
                        .map((item) => item.trim())
                        .filter(Boolean),
                    })
                  }
                />
              </Field>
            </>
          )}
        </Section>
      )}

      <div className="config-actions">
        <button
          type="button"
          disabled={disabled}
          title="Put the values calibrated in this lab back for the chosen detector. Keeps the response settings."
          onClick={() =>
            set(
              config.mode === "entropy"
                ? { entropy: defaultEntropy }
                : {
                    model: defaultDetection.model,
                    prompt: defaultDetection.prompt,
                    llm_max_samples: defaultDetection.llm_max_samples,
                    threshold: defaultDetection.threshold,
                    poll_seconds: defaultDetection.poll_seconds,
                  },
            )
          }
        >
          Restore calibrated values
        </button>
        <button
          type="button"
          disabled={disabled || options.current === undefined}
          title="Copy the detector service's current setup (what scripts/detector.sh last set)."
          onClick={() =>
            setExperiment({
              ...experiment,
              detection: {
                ...detectionFromService(options.current),
                response: { ...defaultResponse, ...config.response },
              },
            })
          }
        >
          Match the detector now
        </button>
        <button type="button" onClick={reload} disabled={locked}>
          Refresh models
        </button>
      </div>
    </div>
  );
}

/** Always-visible switch between the detectors, in the work bar. */
export function DetectorSwitch({
  experiment,
  setExperiment,
  options,
  disabled,
}: {
  experiment: Experiment;
  setExperiment: (value: Experiment) => void;
  options: DetectionOptions;
  disabled: boolean;
}) {
  const config = experiment.detection;
  const installed = options.models?.length
    ? options.models
    : knownModels.map((item) => item.name);
  const models =
    config && !installed.includes(config.model)
      ? [config.model, ...installed]
      : installed;
  const value = !config
    ? "unset"
    : config.mode === "llm"
      ? `llm:${config.model}`
      : config.mode;
  return (
    <label
      className="detector-switch"
      title="Which detector judges the next run. The same choice, with all its settings, is in the Detection tab."
    >
      <span>Detector</span>
      <select
        aria-label="Detector"
        value={value}
        disabled={disabled || !config}
        onChange={(event) => {
          if (!config) return;
          const next = event.target.value;
          setExperiment({
            ...experiment,
            mitigation: next === "off" ? false : experiment.mitigation,
            detection: next.startsWith("llm:")
              ? { ...config, mode: "llm", model: next.slice(4) }
              : { ...config, mode: next as DetectionMode },
          });
        }}
      >
        {!config && (
          <option value="unset">
            {options.available === false ? "not available" : "reading…"}
          </option>
        )}
        {models.map((name) => (
          <option key={name} value={`llm:${name}`}>
            LLM · {name}
          </option>
        ))}
        <option value="entropy">
          Entropy ·{" "}
          {entropyMeasures[config?.entropy.measure ?? defaultEntropy.measure]}
        </option>
        <option value="off">No detection</option>
      </select>
    </label>
  );
}
