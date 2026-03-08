## SOC Framework – Incident Response (NIST)

### Description

The **SOC Framework – Incident Response (NIST)** pack provides a standardized set of incident response workflows aligned with the lifecycle defined in **NIST SP 800-61**. It implements the operational stages of incident response within the SOC Framework, enabling consistent investigation, containment, eradication, recovery, and communication processes across security incidents.

Rather than building separate playbooks for each threat scenario, this pack organizes response logic around the **incident response lifecycle**. Scenarios such as phishing, endpoint compromise, identity abuse, and other security events enter the workflow and progress through the same structured response phases. This approach promotes consistent analyst workflows, reduces duplicated automation logic, and ensures that containment and recovery actions follow a predictable process.

The playbooks in this pack are designed to operate on standardized artifacts and actions provided by the **SOC Framework Core** pack. Vendor-specific commands are abstracted through framework actions, allowing the same incident response logic to operate across different security products and environments.

### Key Capabilities

- Lifecycle-based incident response workflows aligned with **NIST SP 800-61**
- Standardized phases including:
  - **Upon Trigger**
  - **Analysis**
  - **Containment**
  - **Eradication**
  - **Recovery**
  - **Communication**
- Scenario-agnostic workflows that support incidents such as phishing, endpoint compromise, and identity threats
- Integration with the **SOC Framework Core** abstraction layer to execute vendor-specific response actions
- Consistent handling of investigation artifacts and incident context across response phases

### Architecture

By separating **incident response methodology** from **vendor integrations and automation primitives**, this pack allows organizations to maintain a consistent incident response process while adapting to changes in security tooling or detection sources.