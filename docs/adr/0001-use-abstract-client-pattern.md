# ADR 0001: Abstract Client Pattern for External Services

## Status
Accepted

## Context
The sandbox platform integrates multiple external services and execution environments (Kasm Workspaces, E2B, DRAKVUF, MISP) which have varying availability, network requirements, and hardware prerequisites (e.g., DRAKVUF requires Intel VT-x).
We need a software architecture pattern that enables:
- Local development on commodity hardware without external dependencies.
- Graceful degradation when external APIs or hypervisor capabilities are unavailable.
- Reliable testing environments without the need to mock complex logic in every test suite.
- A seamless demo mode for graduation presentations that guarantees reproducibility.

## Decision
We will implement the **Abstract Client Pattern** (or Ports and Adapters) for all external services.
Every external service integration will define an abstract base class (interface). We will provide at least two implementations:
1.  **Simulated Client**: Returns deterministic, reproducible, and safe results. Used for local development, unit testing, and graduation demos.
2.  **Live Client**: Connects to the real service API with proper authentication and error handling. Used in staging and production.

### Example
```python
from abc import ABC, abstractmethod

class KasmClient(ABC):
    @abstractmethod
    async def create_session(self, sample_id: str) -> dict: ...

class SimulatedKasmClient(KasmClient):
    async def create_session(self, sample_id: str) -> dict:
        return {"session_id": "sim_123", "url": "http://localhost:8080/simulated"}

class LiveKasmClient(KasmClient):
    async def create_session(self, sample_id: str) -> dict:
        # Actual HTTP calls to Kasm API
        pass
```

## Consequences

### Positive
- **Testability**: Unit tests can inject the simulated client without executing network calls.
- **Resilience**: The system can fallback to simulation or skip deep analysis if a component fails, rather than crashing.
- **Demo Reliability**: By setting `ENABLE_SIMULATORS=True`, the graduation demo is insulated from network outages or hardware limitations.
- **Extensibility**: It is straightforward to add new isolation backends (e.g., swapping E2B for a custom Kubernetes runner) by simply implementing the interface.

### Negative
- **Overhead**: Slight increase in initial development time to define abstract classes and build realistic simulators.
- **Maintenance**: Simulated clients must be kept up-to-date with changes in the live service API contracts to ensure tests remain valid.

## Compliance
This architectural pattern directly supports the academic project constraints (limited hardware access) while maintaining enterprise production readiness.
