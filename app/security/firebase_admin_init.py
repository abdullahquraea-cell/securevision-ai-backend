"""
Firebase Admin SDK initialization and token verification.
يُحمّل بيانات الاعتماد من متغير البيئة FIREBASE_CREDENTIALS (JSON string).
"""

import json
import os
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

# متغير عام لتخزين حالة التهيئة
_firebase_initialized = False
_firebase_init_error: Optional[str] = None


def _initialize_firebase() -> None:
    """تهيئة Firebase Admin SDK مرة واحدة فقط."""
    global _firebase_initialized, _firebase_init_error

    if _firebase_initialized:
        return

    try:
        import firebase_admin
        from firebase_admin import credentials

        # تجنّب التهيئة المكرّرة
        if firebase_admin._apps:
            _firebase_initialized = True
            return

        # محاولة قراءة بيانات الاعتماد من متغيرات البيئة
        creds_json_str = os.getenv("FIREBASE_CREDENTIALS")

        if not creds_json_str:
            _firebase_init_error = "FIREBASE_CREDENTIALS env var not set"
            logger.warning(
                "[Firebase Admin] FIREBASE_CREDENTIALS not configured — "
                "Firebase token verification is disabled."
            )
            return

        try:
            creds_dict = json.loads(creds_json_str)
        except json.JSONDecodeError as e:
            _firebase_init_error = f"Invalid JSON in FIREBASE_CREDENTIALS: {e}"
            logger.error(f"[Firebase Admin] {_firebase_init_error}")
            return

        cred = credentials.Certificate(creds_dict)
        firebase_admin.initialize_app(cred)
        _firebase_initialized = True
        logger.info("[Firebase Admin] Initialized successfully ✅")

    except ImportError:
        _firebase_init_error = "firebase-admin package not installed"
        logger.warning(
            "[Firebase Admin] firebase-admin not installed — "
            "install with: pip install firebase-admin"
        )
    except Exception as e:
        _firebase_init_error = f"Initialization error: {e}"
        logger.error(f"[Firebase Admin] {_firebase_init_error}")


def verify_firebase_token(id_token: str) -> Optional[Dict[str, Any]]:
    """
    يتحقق من صحة Firebase ID Token ويرجع بياناته المفكوكة.
    يرجع None لو كان التوكن غير صالح أو Firebase غير مهيّأ.
    """
    if not _firebase_initialized:
        _initialize_firebase()

    if not _firebase_initialized:
        return None

    try:
        from firebase_admin import auth as fb_auth
        decoded = fb_auth.verify_id_token(id_token)
        # decoded يحوي: uid, email, email_verified, name, picture, ...
        return decoded
    except Exception as e:
        logger.warning(f"[Firebase Admin] Token verification failed: {e}")
        return None


def is_firebase_ready() -> bool:
    """هل Firebase Admin مهيّأ بشكل صحيح؟"""
    if not _firebase_initialized:
        _initialize_firebase()
    return _firebase_initialized


# تهيئة تلقائية عند استيراد الوحدة
_initialize_firebase()
