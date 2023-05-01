
# About this directory:

This directory contains the following files:

- [`AbuseReport.schema.json`](./AbuseReport.schema.json): A JSON schema file that defines the structure of an abuse report. The schema specifies the required and optional fields for an abuse report, as well as their data types.

- [`C3Audit.schema.json`](./C3Audit.schema.json): A JSON schema file that defines the structure of a C3Audit entry. The schema specifies the required and optional fields for a C3Audit entry, as well as their data types.

- [`FirewallBlockReasons.md`](./FirewallBlockReasons.md): A support document listing the possible values for the `reasonFlag` field in an abuse report. The `reasonFlag` field indicates the reason why a firewall blocked a request. This document provides a list of valid values for the `reasonFlag` field, along with a brief description of each value.

## About the Abuse Report and C3Audit Schemas

The [`AbuseReport.schema.json`](./AbuseReport.schema.json) and [`C3Audit.schema.json`](./C3Audit.schema.json) files define the structure of abuse reports and C3Audit entries, respectively. Abuse reports describe incidents of abuse or misuse of a system or service, while C3Audit entries track and store information about abusive users in the VESNX IDPS package.

The C3Audit class is an industry standard that is widely used for documenting suspicious activity and assisting in cyber crime forensics. Each C3Audit entry typically belongs to an AbuseReport, as indicated by the `AbuseTicket` property in the C3Audit class. This relationship helps to organize and associate C3Audit entries with their corresponding abuse incidents.

To use these schemas, validate your abuse reports and C3Audit entries against them using a JSON schema validator. This will ensure that your data conforms to the required structure and format.

## Firewall Block Reasons

The [`FirewallBlockReasons.md`](./FirewallBlockReasons.md) file provides a list of possible values for the `reasonFlag` field in an abuse report. This field indicates the reason why a firewall blocked a request. The document lists the valid values for the `reasonFlag` field, along with a brief description of each value.

If you encounter a `reasonFlag` value not listed in this document, please contact the appropriate support team for further assistance.

