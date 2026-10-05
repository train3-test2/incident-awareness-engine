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
    return parser.parse_args()


def render(template: str, replacements: dict[str, str | None]) -> str:
    for placeholder, value in replacements.items():
        if placeholder in template:
            if not value:
                message = f"{placeholder} must be supplied for this task definition."
                raise ValueError(message)
            template = template.replace(placeholder, value)

    unresolved = [placeholder for placeholder in replacements if placeholder in template]
    if unresolved:
        message = f"Unresolved placeholders: {', '.join(unresolved)}"
        raise ValueError(message)

    json.loads(template)
    return template


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
        },
    )
    arguments.output.write_text(rendered, encoding="utf-8")


if __name__ == "__main__":
    main()
