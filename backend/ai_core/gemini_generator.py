from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv
from google import genai

BASE_DIR = Path(__file__).resolve().parents[2]
load_dotenv(BASE_DIR / ".env")


class GeminiDocumentGenerator:
    def __init__(self) -> None:
        self.api_key = os.getenv("GEMINI_API_KEY")
        self.model_name = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")

        if not self.api_key:
            raise ValueError("GEMINI_API_KEY is missing. Add it to the project .env file.")

        self.client = genai.Client(api_key=self.api_key)

    def _build_prompt(self, document_details: dict) -> str:
        document_type = document_details.get("document_type", "General Agreement")
        first_party_name = document_details.get("first_party_name") or "[First Party Name]"
        first_party_role = document_details.get("first_party_role") or "[Role]"
        second_party_name = document_details.get("second_party_name") or "[Second Party Name]"
        second_party_role = document_details.get("second_party_role") or "[Role]"
        additional_parties = document_details.get("additional_parties") or "None specified"
        effective_date = document_details.get("effective_date") or "[Effective Date]"
        terms = document_details.get("terms_and_conditions") or "[Terms and conditions]"
        jurisdiction = document_details.get("jurisdiction") or "[Jurisdiction]"
        company_name = document_details.get("optional_company_name") or "[Company Name]"

        return f"""
You are generating a professional legal document draft for {document_type}.

Important rules:
- Do not invent names, dates, addresses, payment amounts, or other missing details.
- Use placeholders like [Full Legal Name], [Address], [Amount], [Date], [Jurisdiction], and [Company Name] whenever information is not provided.
- Preserve the user's specified terms exactly as supplied.
- Use formal, readable legal drafting language.
- Clearly identify the document as an AI-generated draft.
- Do not guarantee legal validity or enforceability.
- Include a recommendation to have the document reviewed by a qualified legal professional.
- If details are missing, state that they should be inserted before use.

User-provided information:
Document Type: {document_type}
First Party: {first_party_name} ({first_party_role})
Second Party: {second_party_name} ({second_party_role})
Additional Parties: {additional_parties}
Optional Company Name: {company_name}
Effective Date: {effective_date}
Jurisdiction: {jurisdiction}
Operating Terms and Conditions: {terms}

Generate a structured legal document draft that includes:
1. Document Title
2. Parties Involved
3. Effective Date
4. Introduction
5. Main Clauses
6. Terms and Conditions
7. Responsibilities of each party
8. Termination clause, where appropriate
9. Signature Sections
10. Missing information that requires attention
11. Legal disclaimer and professional review recommendation

Return the final document as clean plain text only. Do not include markdown code fences or JSON.
Keep it readable and formal.
"""

    def generate_document(self, document_details: dict) -> dict:
        if not document_details:
            raise ValueError("Document details are required.")

        prompt = self._build_prompt(document_details)

        try:
            response = self.client.models.generate_content(
                model=self.model_name,
                contents=prompt,
            )
            generated_text = getattr(response, "text", None)

            if not generated_text or not str(generated_text).strip():
                raise ValueError("The AI service returned an empty response.")

            title = self._create_title(document_details.get("document_type", "General Agreement"))
            return {
                "title": title,
                "document_type": document_details.get("document_type", "General Agreement"),
                "generated_content": str(generated_text).strip(),
                "metadata": {
                    "model": self.model_name,
                    "generated_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
                    "source": "Gemini",
                },
            }
        except Exception as exc:
            message = str(exc)
            if "API key" in message.lower() or "auth" in message.lower():
                raise RuntimeError("The Gemini API key is invalid or missing.") from exc
            if "rate limit" in message.lower() or "429" in message:
                raise RuntimeError("Gemini API is rate-limited. Please try again shortly.") from exc
            if "timeout" in message.lower():
                raise RuntimeError("The Gemini API request timed out. Please try again later.") from exc
            raise RuntimeError("The legal document generator could not complete the request.") from exc

    @staticmethod
    def _create_title(document_type: str) -> str:
        clean_type = (document_type or "General Agreement").strip()
        return f"{clean_type} Draft"
