# VESNX Cybercrime Assistance Schema
![Logo](https:raw.githubusercontent.com/vesnx/VESNX-Cybercrime-Assistance/doc/care-logo.png)

The VESNX Cybercrime Assistance Schema is part of the VESNX C.A.R.E. (Cybercrime Assistance and Legal Representation) project. This repository contains a collection of standardized data objects designed to bridge the gap between abuse victims and the legal community. It aims to streamline the process of reporting and addressing cybercrime incidents by providing clear and structured formats for sharing information.

## Key Features
Standardized data objects for effective communication
Facilitates efficient collaboration between victims and the legal community
Streamlines the process of reporting cybercrime incidents
Provides a clear and structured format for sharing information

##Objects
AbuseReport: A comprehensive object that includes essential details about the abuse incident, such as the source and destination IP addresses, attack type, and more.
More objects will be added in the future.

##Usage
To use the schema, simply include the relevant object definitions in your project and import them as needed.

````#c
using VESNX.Cybercrime.Assistance.Schema;

// Create an AbuseReport instance
AbuseReport report = new AbuseReport
{
    IPAddress = "192.168.1.1",
    AttackType = "DDoS",
    // ... other properties
};

// Serialize the report to JSON
string reportJson = JsonConvert.SerializeObject(report, Formatting.Indented);
````
## Contributing
We welcome contributions to the VESNX Cybercrime Assistance Schema project! If you'd like to contribute, please follow these steps:

1. Fork the repository
2. Create a new branch with your changes
3. Submit a pull request
Please follow our [Code of Conduct](codeofconduct.md) and ensure that your changes are well-documented and follow the established coding standards.

## License
This project is licensed under the MIT License.
