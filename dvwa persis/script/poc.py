from pycti import OpenCTIApiClient

API_URL = "http://localhost:8080/"
API_TOKEN = "05fe83ad-55a9-4771-8016-c8e12a97713a"

opencti_api_client = OpenCTIApiClient(API_URL, API_TOKEN)

try:
    file_observable = opencti_api_client.stix_cyber_observable.create(
        observableData={
            "type": "file",
            "hashes": {
                "md5": "16b3f663d0f0371a4706642c6ac04e42",
                "sha-1": "3a1f908941311fc357051b5c35fd2a4e0c834e37",
                "sha-256": "bcc70a49fab005b4cdbe0cbd87863ec622c6b2c656987d201adbb0e05ec03e56",
            },
            "x_opencti_score": 85,
        }
    )
    print(f"File Observable created: {file_observable}")
except Exception as e:
    print(f"Error creating file observable: {e}")

try:
    process_observable = opencti_api_client.stix_cyber_observable.create(
        observableData={
            "type": "Process",
            "x_opencti_description": "A process",
            "cwd": "C:\\Process.exe",
            "pid": 19000,
            "command_line": "--run exe",
            "x_opencti_score": 90,
        }
    )
    print(f"Process Observable created: {process_observable}")
except Exception as e:
    print(f"Error creating process observable: {e}")

try:
    server_ip_observable = opencti_api_client.stix_cyber_observable.create(
        observableData={
            "type": "IPv4-Addr",
            "value":"172.20.0.1",  # Replace with your server's IP address
            "x_opencti_description": "Server IP address to block",
            "x_opencti_score": 80,  # Added score
        }
    )
    print(f"Server IP Observable created: {server_ip_observable}")
except Exception as e:
    print(f"Error creating server IP observable: {e}")

try:
    Angie_ip_observable = opencti_api_client.stix_cyber_observable.create(
        observableData={
            "type": "IPv4-Addr",
            "value":"172.20.0.1",  # Replace with Angie's actual IP address
            "x_opencti_description": "Angie's device IP address",
            "x_opencti_score": 75,  # Added score
        }
    )
    print(f"Angie IP Observable created: {Angie_ip_observable}")
except Exception as e:
    print(f"Error creating Angie's IP observable: {e}")

try:
    author = opencti_api_client.identity.create(
        name="Angie's device",
        description="poc",
        type="Organization",
    )
    print(f"Author created: {author}")
except Exception as e:
    print(f"Error creating author: {e}")

try:
    # Create relationships between observables and the author
    opencti_api_client.stix_core_relationship.create(
        toId=file_observable["id"],
        fromId=process_observable["id"],
        confidence=90,
        createdBy=author["id"],
        relationship_type="related-to",
        description="Relation between the File and Process objects",
    )
    print("Relationship between File and Process created successfully.")

    opencti_api_client.stix_core_relationship.create(
        toId=server_ip_observable["id"],
        fromId=process_observable["id"],
        confidence=80,
        createdBy=author["id"],
        relationship_type="related-to",
        description="Relation between the server IP address and the Process",
    )
    print("Relationship between Server IP and Process created successfully.")

    opencti_api_client.stix_core_relationship.create(
        toId=Angie_ip_observable["id"],
        fromId=process_observable["id"],
        confidence=70,
        createdBy=author["id"],
        relationship_type="related-to",
        description="Relation between Angie's IP address and the Process",
    )
    print("Relationship between Angie's IP and Process created successfully.")
except Exception as e:
    print(f"Error creating relationships: {e}")

print("Observables and relationships created successfully!")
