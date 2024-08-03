---
description: Instrument LLM calls made using VertexAI's SDK via the VertexAIInstrumentor
---

# VertexAI

The VertexAI SDK can be instrumented using the [`openinference-instrumentation-vertexai`](https://github.com/Arize-ai/openinference/tree/main/python/instrumentation/openinference-instrumentation-vertexai) package.

### Install

```shell
pip install openinference-instrumentation-vertexai vertexai
```

### Setup

See Google's [guide](https://cloud.google.com/vertex-ai/generative-ai/docs/start/quickstarts/quickstart-multimodal#expandable-1) on setting up your environment for the Google Cloud AI Platform.

You can also store your Project ID in the `CLOUD_ML_PROJECT_ID` environment variable.

Set up [OpenTelemetry to point to a running Phoenix Instance](https://docs.arize.com/phoenix/quickstart) and then initialize the VertexAIInstrumentor before your application code.

```python
from openinference.instrumentation.vertexai import VertexAIInstrumentor

VertexAIInstrumentor().instrument()
```

## Run VertexAI

```python
import vertexai
from vertexai.generative_models import GenerativeModel

vertexai.init(location="us-central1")
model = GenerativeModel("gemini-1.5-flash")

print(model.generate_content("Why is sky blue?").text)
```

## Observe

Now that you have tracing setup, all invocations of Vertex models will be streamed to your running Phoenix for observability and evaluation.

## Resources

* [Example notebook](https://github.com/Arize-ai/openinference/blob/main/python/instrumentation/openinference-instrumentation-vertexai/examples/basic\_generation.py)
* [OpenInference package](https://github.com/Arize-ai/openinference/blob/main/python/instrumentation/openinference-instrumentation-vertexai)
* [Working examples](https://github.com/Arize-ai/openinference/blob/main/python/instrumentation/openinference-instrumentation-vertexai/examples)
