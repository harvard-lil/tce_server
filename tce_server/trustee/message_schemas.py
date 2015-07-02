message_schema = {
    "type": "object",
    "oneOf": [
        {
            "properties": {
                "action": {"enum": ["generate_contract_keypair"]},
                "uuid": {"$ref": "#/definitions/uuid"},
            },
            "required": ["uuid", "action"],
            "additionalProperties": False,
        },
        {
            "properties": {
                "action": {"enum": ["generate_share"]},
                "uuid": {"$ref": "#/definitions/uuid"},
                "contract_public_keys": {
                    "type": "array",
                    "minItems": 2,
                    "items": {"type": "string"},
                    "uniqueItems": True
                },
                "recovery_threshold": {"type": "integer", "minimum": 1},
            },
            "required": ["uuid", "action", "contract_public_keys"],
            "additionalProperties": False,
        },
        {
            "properties": {
                "action": {"enum": ["validate_combined_key"]},
                "uuid": {"$ref": "#/definitions/uuid"},
                "state": {"type": "string"},
                "combined_gpg_key": {"type": "string"},
            },
            "required": ["uuid", "action", "state", "combined_gpg_key"],
            "additionalProperties": False,
        },
    ],
    "definitions": {
        "uuid":{
            "type": "string",
            "pattern": "^[a-zA-Z0-9\-]+$"
        }
    },
}

contract_schema = {
    "type": "object",
    "properties": {
        "release_date": {"type": "string"},
        "recovery_threshold": {"type": "integer", "minimum": 1},
        "share_count": {"type": "integer", "minimum": 1},
    },
    "required": ["release_date", "recovery_threshold", "share_count"],
    "additionalProperties": False,
}

state_schema = {
    "type": "object",
    "properties": {
        "uuid": {"type":"string"},
        "contract": contract_schema,
        "shares": {
            "type": "array",
            "minItems": 2,
            "items": {
                "type": "object",
                "properties": {
                    "contract_public_key": {"type": "string"},
                    "x": {"type": "string"},
                    "y": {"type": "string"},
                    "commitments": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                    "subshares": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                },
                "required": ["x", "y", "commitments", "subshares"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["uuid", "contract", "shares"],
    "additionalProperties": False,
}

gpg_schema = {
    "type": "object",
    "properties": {
        "uuid": {"type": "string"},
        "contract": contract_schema,
        "state_digest": {"type": "string"},
    },
    "required": ["uuid", "contract", "state_digest"],
    "additionalProperties": False,
}