from app.services.analyzers.resource_analyzer import ResourceAnalyzer


def test_resource_extraction_and_relationships():
    endpoints = [
        {
            "method": "GET",
            "path": "/patients",
            "parameters": []
        },
        {
            "method": "POST",
            "path": "/patients",
            "parameters": []
        },
        {
            "method": "GET",
            "path": "/patients/{id}",
            "parameters": [{"name": "id", "location": "path"}]
        },
        {
            "method": "POST",
            "path": "/patients/{id}/appointments",
            "parameters": [{"name": "id", "location": "path"}]
        },
        {
            "method": "POST",
            "path": "/payments",
            "parameters": [{"name": "patient_id", "location": "query"}]
        }
    ]

    analyzer = ResourceAnalyzer()
    res = analyzer.analyze(endpoints)
    resource_names = [r.name for r in res.resources]

    assert "Patient" in resource_names
    patient_res = next(r for r in res.resources if r.name == "Patient")
    assert "create" in patient_res.crud_operations
    assert "list" in patient_res.crud_operations
    assert "read" in patient_res.crud_operations

    assert any(rel.target_resource == "Appointment" for rel in patient_res.relationships)
