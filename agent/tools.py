from markitdown import MarkItDown
from typing import Any, Callable
import requests

class Tool:
    """A callable tool the agent can invoke."""

    def __init__(
        self, name: str, description: str, parameters: dict, handler: Callable[..., str]
    ) -> None:
        self.name = name
        self.description = description
        self.parameters = parameters
        self.handler = handler

    def to_openai_spec(self) -> dict:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }

    def run(self, **kwargs: Any) -> str:
        return self.handler(**kwargs)


def fetch_webpage(url: str) -> str:
    """Fetch a webpage and return its text content."""
    try:
        jina_ai_url = "https://r.jina.ai/"
        response = requests.get(jina_ai_url + url)
        response.raise_for_status()
        return response.text
    except Exception as e:
        md = MarkItDown()
        return md.convert(url).text_content

FETCH_WEBPAGE_TOOL = Tool(
    name="fetch_webpage",
    description="Fetch the content of a webpage and return its text",
    parameters={
        "type": "object",
        "properties": {
            "url": {
                "type": "string",
                "description": "The URL to fetch",
            }
        },
        "required": ["url"],
    },
    handler=fetch_webpage,
)
