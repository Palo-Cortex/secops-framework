# SOC Framework for Cortex XSIAM

The operating layer for security operations on Cortex XSIAM, and the lifecycles that run on it. The framework makes any lifecycle vendor-agnostic, safe to run and measurable: every vendor action goes through one command, every changing action ships simulated until it is switched on, and every action writes one row with the analyst minutes it stands for. A lifecycle, such as NIST IR AI, decides what to ask and when to act; the framework decides how an action is carried out, on which vendor, whether it really runs, and what gets recorded.

**Documentation: [palo-cortex.github.io/secops-framework](https://palo-cortex.github.io/secops-framework/)**

## Start here, by what you are doing

| You want to | Go to |
|---|---|
| Understand what the framework is and what a lifecycle is, in one page | [Framework and Lifecycle](https://palo-cortex.github.io/secops-framework/) |
| Stand it up on a tenant and see what it would do, without changing anything | [Evaluate](https://palo-cortex.github.io/secops-framework/evaluate/) — [install](https://palo-cortex.github.io/secops-framework/evaluate/install/) takes about 30 minutes |
| Keep producing the same measures in production | [Deploy to production](https://palo-cortex.github.io/secops-framework/deploy/) |
| Write content that fits the framework and get it through the gates | [Build on the framework](https://palo-cortex.github.io/secops-framework/build/) |
| Look up one capability: its switch, how to turn it on, how to verify it | [Reference](https://palo-cortex.github.io/secops-framework/reference/) |
| Find out why something did not behave | [Support](https://palo-cortex.github.io/secops-framework/support/) |

## What is in this repository

| Path | What it holds |
|---|---|
| `Packs/soc-optimization-unified/` | The framework: the universal command, Shadow Mode, lists, datasets, scripts, dashboards. Its [README](Packs/soc-optimization-unified/README.md) is the capability catalog. |
| `Packs/soc-framework-nist-ir-ai/` | The NIST IR AI lifecycle: assessment, close decision, case analysis, layouts, dashboards. |
| `ai/nist-ir/` | The lifecycle's hand-deployed playbooks and prompt recipes, with their release notes. |
| `Packs/soc-*` | Vendor packs: one per data source, generated from a contract under `schemas/vendors/`. |
| `schemas/` | The contracts the content is generated from and validated against. |
| `tools/` | The gates and generators: `check_contribution.py` before every commit, `prep_docs.py` for the docs. |
| `docs/` | The site source. `docs/nav.yml` is the site map; generated pages carry a banner and are never edited by hand. |

Releases are cut per pack from `main`; tenants install them through the SOC Framework Pack Manager. See [Contributing](CONTRIBUTING.md) and the [Build](https://palo-cortex.github.io/secops-framework/build/) tab for the branch, gate and release flow.

## License

See [LICENSE.txt](LICENSE.txt).
