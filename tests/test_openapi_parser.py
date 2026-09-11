import pytest
from app.core.exceptions import SpecParsingError
from app.services.openapi_parser.parser import OpenAPIParser


def test_valid_yaml_parsing():
    yaml_spec = """
    openapi: 3.0.0
    info:
      title: Test API
      version: 1.0.0
    paths:
      /users/{id}:
        get:
          summary: Get user
          parameters:
            - name: id
              in: path
              required: true
              schema:
                type: string
          responses:
            '200':
              description: OK
    """
    parser = OpenAPIParser(yaml_spec)
    meta = parser.get_metadata()
    assert meta["title"] == "Test API"
    assert meta["version"] == "1.0.0"
    assert meta["openapi_version"] == "3.0.0"

    endpoints = parser.get_endpoints()
    assert len(endpoints) == 1
    assert endpoints[0]["path"] == "/users/{id}"
    assert endpoints[0]["method"] == "GET"
    assert len(endpoints[0]["parameters"]) == 1
    assert endpoints[0]["parameters"][0]["name"] == "id"


def test_valid_json_parsing():
    json_spec = """{
      "swagger": "2.0",
      "info": {
        "title": "Swagger Test",
        "version": "2.1.0"
      },
      "paths": {
        "/items": {
          "post": {
            "summary": "Create item",
            "responses": {
              "201": { "description": "Created" }
            }
          }
        }
      }
    }"""
    parser = OpenAPIParser(json_spec)
    meta = parser.get_metadata()
    assert meta["title"] == "Swagger Test"
    assert meta["openapi_version"] == "2.0"

    endpoints = parser.get_endpoints()
    assert len(endpoints) == 1
    assert endpoints[0]["method"] == "POST"
    assert endpoints[0]["path"] == "/items"


def test_ref_resolution():
    spec_with_ref = """
    openapi: 3.0.0
    info:
      title: Ref Test API
      version: 1.0.0
    paths:
      /accounts:
        post:
          summary: Create account
          requestBody:
            content:
              application/json:
                schema:
                  $ref: '#/components/schemas/AccountInput'
          responses:
            '200':
              description: OK
    components:
      schemas:
        AccountInput:
          type: object
          properties:
            account_number:
              type: string
            balance:
              type: number
    """
    parser = OpenAPIParser(spec_with_ref)
    endpoints = parser.get_endpoints()
    schemas = endpoints[0]["schemas"]
    assert len(schemas) == 1
    assert schemas[0]["schema_json"]["type"] == "object"
    assert "account_number" in schemas[0]["schema_json"]["properties"]


def test_malformed_spec_empty():
    with pytest.raises(SpecParsingError):
        OpenAPIParser("")


def test_malformed_spec_invalid_syntax():
    with pytest.raises(SpecParsingError):
        OpenAPIParser("{ invalid json : : : }")


def test_missing_version():
    spec = """
    info:
      title: Missing version spec
    paths: {}
    """
    with pytest.raises(SpecParsingError):
        OpenAPIParser(spec)
