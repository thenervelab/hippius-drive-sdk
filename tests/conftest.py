import pytest


@pytest.fixture
def anyio_backend() -> str:
    """Run every `@pytest.mark.anyio` test on asyncio only; trio is not a dependency."""
    return "asyncio"
