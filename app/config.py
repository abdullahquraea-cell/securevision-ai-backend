from pydantic_settings import BaseSettings


class Settings(BaseSettings):

    DATABASE_URL: str

    ANTHROPIC_API_KEY: str

    # مفتاح JWT (له قيمة افتراضية للتطوير، لكن يُفضّل وضعه في .env)
    JWT_SECRET_KEY: str = "dev-secret-change-me"

    # النطاقات المسموح لها (مفصولة بفواصل)
    ALLOWED_ORIGINS: str = "http://localhost:5173,http://127.0.0.1:5173"

    # Stripe
    STRIPE_SECRET_KEY: str = ""
    STRIPE_PUBLISHABLE_KEY: str = ""

    # رابط الواجهة (يُستخدم في روابط الدفع والعودة)
    FRONTEND_URL: str = "http://localhost:5173"

    class Config:
        env_file = ".env"
        extra = "ignore"


settings = Settings()