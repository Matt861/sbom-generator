import subprocess
import json
import uuid
import os


def generate_cyclonedx_sbom_via_maven(pom_file):
    # Use Maven to generate the SBOM
    command = [
        "mvn.cmd",
        "org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom",
        f"-f={pom_file}"
    ]

    result = subprocess.run(command, capture_output=True, text=True)

    if result.returncode != 0:
        print("Error generating SBOM:", result.stderr)
        raise Exception("Failed to generate SBOM using Maven")

    # The SBOM is typically generated at `target/bom.json`
    project_dir = os.path.dirname(pom_file)
    return os.path.join(project_dir, "target", "bom.json")


def load_cyclonedx_sbom(file_path):
    with open(file_path, 'r') as f:
        return json.load(f)


def clean_bom_ref_or_purl(value):
    if value and "?type=" in value:
        return value.split("?type=")[0]
    return value


def generate_custom_sbom(cyclonedx_bom):
    # Convert CycloneDX SBOM to custom format
    custom_sbom = {
        "bomFormat": cyclonedx_bom.get("bomFormat", "CycloneDX"),
        "specVersion": cyclonedx_bom.get("specVersion", "1.3"),
        "serialNumber": f"urn:uuid:{str(uuid.uuid4())}",
        "version": 1,
        "metadata": {
            "component": {
                "bom-ref": clean_bom_ref_or_purl(
                    cyclonedx_bom.get("metadata", {}).get("component", {}).get("bom-ref", "")),
                "name": cyclonedx_bom.get("metadata", {}).get("component", {}).get("name", ""),
                "type": "Application",
                "version": cyclonedx_bom.get("metadata", {}).get("component", {}).get("version", "")
            },
            "tools": [
                {
                    "vendor": "MY VENDOR",
                    "name": "MY VENDOR",
                    "version": "0.1.0",
                    "hashes": []
                }
            ]
        },
        "components": [
            {
                "bom-ref": clean_bom_ref_or_purl(component.get("bom-ref", "")),
                "name": component.get("name", ""),
                "group": component.get("group", ""),
                "version": component.get("version", ""),
                "publisher": "Unknown",  # Customize as needed
                "description": component.get("description", ""),
                "type": component.get("type", "Library"),
                "purl": clean_bom_ref_or_purl(component.get("purl", "")),
                "scope": "compile",  # Customize as needed
                "externalReferences": component.get("externalReferences", []),
                "licenses": component.get("licenses", []),
                # "licenses": [
                #     {
                #         "license": {
                #             "id": license.get("id") or license.get("expression")
                #         }
                #     } for license in component.get("licenses", [])
                # ]
            } for component in cyclonedx_bom.get("components", [])
        ],
        "dependencies": [
            {
                "ref": clean_bom_ref_or_purl(dependency.get("ref", "")),
                "dependsOn": [
                    clean_bom_ref_or_purl(dep) for dep in dependency.get("dependsOn", [])
                ]
            } for dependency in cyclonedx_bom.get("dependencies", [])
        ]
    }

    return custom_sbom


def save_sbom(sbom_data, output_file):
    with open(output_file, 'w') as f:
        json.dump(sbom_data, f, indent=4)


def main():
    pom_file = "./input/pom.xml"  # Replace with your actual pom.xml file path
    output_file = "./sboms/maven_sbom.json"  # Replace with your desired output file path

    # Generate the CycloneDX SBOM using Maven
    cyclonedx_sbom_file = generate_cyclonedx_sbom_via_maven(pom_file)

    # Load the generated CycloneDX SBOM
    cyclonedx_bom = load_cyclonedx_sbom(cyclonedx_sbom_file)

    # Convert and save the custom SBOM
    custom_sbom = generate_custom_sbom(cyclonedx_bom)
    save_sbom(custom_sbom, output_file)

    print(f"Custom SBOM generated and saved to {output_file}")


if __name__ == "__main__":
    main()


def run():
    main()
