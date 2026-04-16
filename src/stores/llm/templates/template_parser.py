import os
from langdetect import detect
from langdetect.lang_detect_exception import LangDetectException

class TemplateParser:

    def __init__(self, language: str=None, default_language='en'):
        self.current_path = os.path.dirname(os.path.abspath(__file__))
        self.default_language = default_language
        self.language = None
        self.supported_languages = ['en', 'ar']  # Add supported languages

        self.set_language(language)


    def set_language(self, language: str):
        if not language:
            self.language = self.default_language
        else:
            # Check if the language is supported
            if language in self.supported_languages:
                language_path = os.path.join(self.current_path, "locales", language)
                if os.path.exists(language_path):
                    self.language = language
                else:
                    self.language = self.default_language
            else:
                self.language = self.default_language

    def detect_language(self, text: str) -> str:
        """
        Detect the language of the given text.
        Returns the detected language code or default language if detection fails.
        """
        if not text or not isinstance(text, str):
            return self.default_language

        # Check for Arabic characters first
        import re
        if re.search(r'[\u0600-\u06FF]', text):
            return 'ar'

        try:
            detected_lang = detect(text.strip())
            # Map detected languages to supported languages
            if detected_lang == 'ar':
                return 'ar'
            else:
                return 'en'  # Default to English for all other languages
        except LangDetectException:
            # If detection fails, return default language
            return self.default_language

    def set_language_from_text(self, text: str):
        """
        Automatically set the language based on the detected language in the text.
        """
        detected_lang = self.detect_language(text)
        self.set_language(detected_lang)

    def get(self, group: str, key: str, vars: dict={}):
        if not group or not key:
            return None

        # Force English for rag group to ensure JSON compliance
        targeted_language = "en" if group == "rag" else self.language

        group_path = os.path.join(self.current_path, "locales", targeted_language, f"{group}.py" )
        if not os.path.exists(group_path):
            group_path = os.path.join(self.current_path, "locales", self.default_language, f"{group}.py" )
            targeted_language = self.default_language

        if not os.path.exists(group_path):
            return None

        # import group module
        module = __import__(f"stores.llm.templates.locales.{targeted_language}.{group}", fromlist=[group])

        if not module:
            return None

        key_attribute = getattr(module, key)
        return key_attribute.substitute(vars)