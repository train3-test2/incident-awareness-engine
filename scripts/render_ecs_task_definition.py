"""Render an ECS task-definition template with deployment-time identifiers."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--template", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--image-uri", required=True)
    parser.add_argument("--execution-role-arn", required=True)
    parser.add_argument("--task-role-arn")
    parser.add_argument("--database-url-secret-arn")
    parser.add_argument("--sqs-queue-url")
    parser.add_argument("--s3-input-bucket")
    parser.add_argument("--evaluation-snapshot-s3-uri")
    return parser.parse_args()


def render(template: str, replacements: dict[str, str | None]) -> str:
    definition = json.loads(template)

    def replace_values(value: object) -> object:
        if isinstance(value, str):
            for placeholder, replacement in replacements.items():
                if placeholder in value:
                    if not replacement:
                        message = f"{placeholder} must be supplied for this task definition."
                        raise ValueError(message)
                    value = value.replace(placeholder, replacement)
            return value
        if isinstance(value, list):
            return [replace_values(item) for item in value]
        if isinstance(value, dict):
            return {
                key: item if key == "name" else replace_values(item) for key, item in value.items()
            }
        return value

    rendered_definition = replace_values(definition)
    rendered = json.dumps(rendered_definition, indent=2) + "\n"

    def has_placeholder_value(value: object, placeholder: str) -> bool:
        if isinstance(value, str):
            return placeholder in value
        if isinstance(value, list):
            return any(has_placeholder_value(item, placeholder) for item in value)
        if isinstance(value, dict):
            return any(
                has_placeholder_value(item, placeholder)
                for key, item in value.items()
                if key != "name"
            )
        return False

    unresolved = [
        placeholder
        for placeholder in replacements
        if has_placeholder_value(rendered_definition, placeholder)
    ]
    if unresolved:
        message = f"Unresolved placeholders: {', '.join(unresolved)}"
        raise ValueError(message)

    return rendered


def main() -> None:
    arguments = parse_arguments()
    template = arguments.template.read_text(encoding="utf-8")
    rendered = render(
        template,
        {
            "IMAGE_URI": arguments.image_uri,
            "EXECUTION_ROLE_ARN": arguments.execution_role_arn,
            "TASK_ROLE_ARN": arguments.task_role_arn,
            "DATABASE_URL_SECRET_ARN": arguments.database_url_secret_arn,
            "SQS_QUEUE_URL": arguments.sqs_queue_url,
            "S3_INPUT_BUCKET": arguments.s3_input_bucket,
            "EVALUATION_SNAPSHOT_S3_URI": arguments.evaluation_snapshot_s3_uri,
        },
    )
    arguments.output.write_text(rendered, encoding="utf-8")


if __name__ == "__main__":
    main()
