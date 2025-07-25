# Trust Policy for Upstream Trust List Inclusion

## Purpose

This document outlines the criteria and evaluation process used to determine whether a trust list may be included as an upstream data source in the Trusted Issuer Registry. The intent is to provide assurance to integrators, fintech organizations, and relying parties that all upstream sources are carefully vetted and meet a baseline standard of transparency, integrity, and operational reliability.

## Criteria for Inclusion

A trust list may be considered for inclusion if it meets all of the following:

- **Public Legitimacy**  
  The trust list is sponsored or recognized by a governmental, industry-standard, or widely trusted public authority.

- **Completeness**  
  The trust list is available in a machine-readable format, and contains all information necessary for RPs to verify digital credentials against their listed issuers.

- **Organizational Accountability**  
  The governing body of the trust list has a clear ownership structure and a published point of contact for trust policy inquiries.

- **Availability and Stability**  
  The trust list is accessible via a reliable endpoint, with reasonable uptime guarantees and long-term maintenance commitments.

## Evaluation Process

Each candidate trust list is reviewed using the following steps:

1. **Initial Assessment**  
   Maintainers evaluate the trust list against the inclusion criteria listed above.

2. **Documentation Review**  
   Review of official specifications, governance models, and published trust anchors or issuer metadata.

3. **Community Discussion**  
   Optional open discussion via GitHub Issues or Discussions, especially for trust lists with evolving policies.

4. **Pull Request for Inclusion**  
   A maintainer submits a PR to add the trust list as an upstream source. This must include:
   - Source URL(s)
   - How to extract and verify data from the Trusted List
   - Summary of why the trust list qualifies

5. **Peer Review**  
   The PR must be approved by a maintainer before merging.

## Criteria for Removal

A trust trust list may be removed if:

- It ceases to operate or maintain its trust list.
- It loses public legitimacy (e.g., becomes defunct, compromised, or replaced).
- It is discovered to have included issuers that no longer meet expected levels of security or compliance.
- Maintainers determine that it violates this policy or undermines the registry’s integrity.

All removals must be submitted as a pull request and undergo the same peer review and public discussion process as inclusions.

## Governance and Oversight

The list of accepted upstream trust lists is maintained by the Trusted Issuer Registry maintainers. Decisions are subject to community review and may be revisited as trust lists evolve. We encourage stakeholders, especially financial institutions and relying parties, to submit feedback or concerns via GitHub Issues.

### Review Process

- Validate trust list URLs
- Check if any schema changes have occurred or are scheduled for each trust list
- Review any complaints that occurred for issuers each trust list provides

_GitHub Actions will be used to automatically create an issue every month to start the review process_

## Disclaimers and Limitations

This policy governs the curation of upstream trust trust lists only. It does not imply endorsement of specific issuers within those lists, nor does it guarantee the legal validity of credentials issued by them. Consumers of this registry are responsible for verifying compliance with their own regulatory or risk requirements.
