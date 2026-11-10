"""Same-origin read-only proxy; the remote target and credentials are server configuration."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Response

from incident_awareness.dashboard.track_b_observations import (
    ObservationEnvelope,
    ObservationQuery,
    RemoteObservationReader,
    RemoteSettings,
)

router = APIRouter(tags=["live-observations"])


def get_observation_reader():
    try:
        settings = RemoteSettings.from_environment()
        if settings.enabled:
            settings.validate()
        return RemoteObservationReader(settings)
    except ValueError as error:
        raise HTTPException(503, "Track-B configuration unavailable") from error


@router.get("/operations/observations", response_model=ObservationEnvelope)
def observations(
    query: Annotated[ObservationQuery, Query()],
    response: Response,
    reader: Annotated[RemoteObservationReader, Depends(get_observation_reader)],
):
    response.headers["Cache-Control"] = "no-store"
    try:
        return reader.read(tuple(query.run_id) if query.run_id else None)
    except LookupError as error:
        raise HTTPException(404, "Unregistered Track-B Run") from error
