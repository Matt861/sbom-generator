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


def load_json_file(template_file):
    with open(template_file, "r") as file:
        template = json.load(file)
    return template


def replace_placeholders(data, replacements):
    if isinstance(data, dict):
        return {key: replace_placeholders(value, replacements) for key, value in data.items()}
    elif isinstance(data, list):
        return [replace_placeholders(item, replacements) for item in data]
    elif isinstance(data, str):
        return data.format(**replacements)
    else:
        return data


def fill_component_template(template, component_info):
    return replace_placeholders(template, component_info)


def fill_sbom_template(template, package_manager):
    replacements = {
        "serialNumber": str(uuid.uuid4()),
        "component_bom_ref": f"{package_manager}-packages@0.1.0",
        "component_name": f"{package_manager}-packages",
        "component_version": "0.1.0",
        "tool_vendor": "LMCO",
        "tool_name": "SSCRM",
        "tool_version": "0.1.0",
        "package_manager": package_manager
    }
    return replace_placeholders(template, replacements)


def generate_custom_sbom(cyclonedx_bom, sbom_components, sbom_dependencies, component_template, package_manager):

    # Convert CycloneDX SBOM to custom format
    for maven_component in cyclonedx_bom.get("components", []):
        component_bom_ref_or_purl = clean_bom_ref_or_purl(maven_component.get("bom-ref", ""))
        component_info = {
            "component_bom_ref": component_bom_ref_or_purl,
            "component_name": maven_component.get("name", ""),
            "component_group": maven_component.get("group", ""),
            "component_version": maven_component.get("version", ""),
            "component_publisher": "Unknown",
            "component_description": maven_component.get("description", ""),
            "component_type": maven_component.get("type", ""),
            "component_purl": component_bom_ref_or_purl,
            "component_scope": maven_component.get("scope", ""),
            "package_manager": package_manager
        }

        component = fill_component_template(component_template, component_info)
        component["licenses"] = maven_component.get("licenses", [])
        component["externalReferences"] = maven_component.get("externalReferences", [])
        sbom_components.append(component)

    for dependency in cyclonedx_bom.get("dependencies", []):
        depends_on = []
        for dep in dependency.get("dependsOn", []):
            depends_on.append(clean_bom_ref_or_purl(dep))

        sbom_dependencies.append({
            "ref": clean_bom_ref_or_purl(dependency.get("ref", "")),
            "dependsOn": depends_on
        })


def save_sbom(sbom_data, output_file):
    with open(output_file, 'w') as f:
        json.dump(sbom_data, f, indent=4)


def main():
    pom_file = "../input/pom.xml"  # Replace with your actual pom.xml file path
    output_file = "../sboms/maven_sbom.json"  # Replace with your desired output file path

    # Generate the CycloneDX SBOM using Maven
    cyclonedx_sbom_file = generate_cyclonedx_sbom_via_maven(pom_file)

    # Load the generated CycloneDX SBOM
    cyclonedx_bom = load_cyclonedx_sbom(cyclonedx_sbom_file)

    # Load the SBOM and component templates
    sbom_template = load_json_file("../templates/sbom_template.json")
    component_template = load_json_file("../templates/sbom_component_template_maven.json")

    package_manager = "maven"  # Set your package manager here

    sbom = fill_sbom_template(sbom_template, package_manager)

    # Convert and save the custom SBOM
    generate_custom_sbom(cyclonedx_bom, sbom["components"], sbom["dependencies"], component_template, package_manager)
    save_sbom(sbom, output_file)

    print(f"Custom SBOM generated and saved to {output_file}")


if __name__ == "__main__":
    main()


def run():
    main()
