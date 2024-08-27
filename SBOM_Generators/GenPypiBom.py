import subprocess
import os
import sys
import venv
import shutil
import requests
import json
import uuid
from pathlib import Path

p = Path(__file__).resolve()


def create_virtualenv(env_dir):
    venv.create(env_dir, with_pip=False)
    python_executable = os.path.join(env_dir, 'bin', 'python') if os.name != 'nt' else os.path.join(env_dir, 'Scripts',
                                                                                                    'python.exe')
    return python_executable


def download_get_pip(python_executable):
    get_pip_url = "https://bootstrap.pypa.io/get-pip.py"
    get_pip_path = "get-pip.py"
    try:
        response = requests.get(get_pip_url)
        response.raise_for_status()
        with open(get_pip_path, 'wb') as f:
            f.write(response.content)
    except requests.exceptions.RequestException as e:
        print(f"Failed to download get-pip.py: {e}")
        sys.exit(1)

    try:
        subprocess.run([python_executable, get_pip_path], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Failed to install pip: {e.stderr}")
        sys.exit(1)
    finally:
        if os.path.exists(get_pip_path):
            os.remove(get_pip_path)


def capture_installed_packages(python_executable):
    result = subprocess.run([python_executable, "-m", "pip", "list", "--no-cache-dir", "--format=freeze"],
                            stdout=subprocess.PIPE, text=True, check=True)
    return set(result.stdout.splitlines())


def install_dependencies(python_executable, requirements_file):
    try:
        subprocess.run([python_executable, "-m", "pip", "install", "--no-cache-dir", "-r", requirements_file],
                       check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error installing dependencies: {e.stderr}")
        sys.exit(1)


def get_dependency_tree(python_executable):
    try:
        subprocess.run([python_executable, "-m", "pip", "install", "pipdeptree"], check=True)
        result = subprocess.run([python_executable, "-m", "pipdeptree", "--warn", "silence"],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True, encoding='utf-8')
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error generating dependency tree: {e.stderr}")
        sys.exit(1)


def parse_dependency_tree(dependency_tree, relevant_packages, python_executable):
    parent_map = {}
    current_parent = None

    for line in dependency_tree.splitlines():
        if not line.strip():
            continue

        # Check if the line is a child package
        if "├──" in line or "└──" in line:
            package_info = line.split('[')[0].split()  # Extracts 'six' from '└── six'
            package_name = package_info[1].lower()
            version_info = line.split('installed: ')[-1].strip(']')
            child_package = f"{package_name}=={version_info}"

            if current_parent:
                if current_parent not in parent_map:
                    parent_map[current_parent] = []
                if child_package not in parent_map[current_parent]:  # Prevent duplicate children
                    parent_map[current_parent].append(child_package)

        else:  # Parent package
            package_name_version = line.split()[0].strip()
            if package_name_version in relevant_packages:
                current_parent = package_name_version
                if current_parent not in parent_map:
                    parent_map[current_parent] = []
            else:
                # Reset current_parent if the new package is not in relevant_packages
                current_parent = None

    # Ensure all relevant packages are included as parents
    for package in relevant_packages:
        if package not in parent_map:
            parent_map[package] = []

    return parent_map


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


def generate_sbom(parent_map, sbom_components, sbom_dependencies, component_template, package_manager):
    # Generate components list
    for parent, children in parent_map.items():
        parent_name, parent_version = parent.lower().split("==")
        pypi_info = fetch_pypi_info(parent_name, parent_version)
        purl = f"{parent_name}@{parent_version}"  # Without "pkg:npm/" prefix for the bom-ref
        parent_purl = f"pkg:{package_manager}/{purl}"  # Full purl with "pkg:{package_manager}/" prefix

        if pypi_info:
            info = pypi_info.get('info', {})
            project_urls = info.get('project_urls', {})
            external_references = []
            for key, url in project_urls.items():
                if "github.com" in url.lower():
                    external_references.append({"type": "vcs", "url": url})
                else:
                    external_references.append({"type": key.lower(), "url": url})

            component_info = {
                "component_bom_ref": purl,
                "component_name": parent_name,
                "component_version": parent_version,
                "component_publisher": info.get('author', 'Unknown'),
                "component_description": info.get('summary', 'No description available'),
                "component_purl": purl,
                "license_id": info.get("license", "Unknown"),
                "package_manager": package_manager
            }

            component = fill_component_template(component_template, component_info)
            component["externalReferences"] = external_references
            sbom_components.append(component)

    # Generate dependencies list
    for parent, children in parent_map.items():
        parent_purl = f"pkg:{package_manager}/{parent.lower().split('==')[0]}@{parent.split('==')[1]}"
        depends_on = [
            f"pkg:{package_manager}/{child.lower().split('==')[0]}@{child.split('==')[1]}" for child in children
        ]
        dependency = {
            "ref": parent_purl,
            "dependsOn": depends_on
        }
        sbom_dependencies.append(dependency)


def add_top_level_dependencies(sbom, requirements_txt, package_manager):
    top_level_refs = []
    with open(requirements_txt, 'r') as file:
        for line in file:
            line = line.strip()
            if line and line.startswith('#'):
                continue
            elif line and "==" in line:  # Ensure the line is not empty and contains '=='
                name, version = line.lower().split('==', 1)
                top_level_refs.append(f"pkg:{package_manager}/{name}@{version.lstrip('^~<>')}")

    top_level_entry = {
        "ref": sbom["metadata"]["component"]["bom-ref"],
        "dependsOn": top_level_refs
    }

    sbom["dependencies"].insert(0, top_level_entry)


def fetch_pypi_info(package_name, version):
    url = f"https://pypi.org/pypi/{package_name}/{version}/json"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Failed to fetch data for {package_name}=={version}")
        return None


def main():
    requirements_file = "../input/requirements.txt"
    if not os.path.exists(requirements_file):
        print(f"{requirements_file} does not exist.")
        return

    env_dir = ".temp_env"
    if os.path.exists(env_dir):
        shutil.rmtree(env_dir)

    python_executable = create_virtualenv(env_dir)

    # Manually install pip in the virtual environment
    download_get_pip(python_executable)

    # Capture the list of installed packages before installing dependencies
    pre_install_packages = capture_installed_packages(python_executable)

    # Install the specified dependencies
    install_dependencies(python_executable, requirements_file)

    # Capture the list of installed packages after installation
    post_install_packages = capture_installed_packages(python_executable)

    # Determine relevant packages (newly installed ones)
    relevant_packages = post_install_packages - pre_install_packages

    # Generate the dependency tree
    dependency_tree = get_dependency_tree(python_executable)

    # Parse the dependency tree to filter only relevant packages
    parent_map = parse_dependency_tree(dependency_tree, relevant_packages, python_executable)

    # Load the SBOM and component templates
    sbom_template = load_json_file("../templates/sbom_template.json")
    component_template = load_json_file("../templates/sbom_component_template.json")

    package_manager = "pypi"  # Set your package manager here

    sbom = fill_sbom_template(sbom_template, package_manager)
    generate_sbom(parent_map, sbom["components"], sbom["dependencies"], component_template, package_manager)
    add_top_level_dependencies(sbom, requirements_file, package_manager)

    # Write SBOM to a file
    with open("../sboms/pypi_sbom.json", "w") as sbom_file:
        json.dump(sbom, sbom_file, indent=4)

    print("SBOM.json generated successfully!")

    shutil.rmtree(env_dir)


if __name__ == "__main__":
    main()


def run():
    main()