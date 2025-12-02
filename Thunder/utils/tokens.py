# Thunder/utils/tokens.py (Updated)

import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
import asyncio
import random
import pyrogram.errors
from Thunder.utils.database import db
from Thunder.vars import Var
from Thunder.utils.logger import logger

async def check(user_id: int) -> bool:
    try:
        logger.debug(f"Token validation started for user: {user_id}")
        if not getattr(Var, "TOKEN_ENABLED", False):
            logger.debug("Token system disabled - access granted")
            return True
        if user_id == Var.OWNER_ID or user_id in Var.AUTH_USERS: # <-- AUTH_USERS check added here
            logger.debug("Owner/Auth User access granted")
            return True
        current_time = datetime.utcnow()
        
        # NOTE: authorize() function uses authorized_users_col, so we check it here too
        auth_result = await db.authorized_users_col.find_one(
            {"user_id": user_id},
            {"_id": 1}
        )
        if auth_result:
            logger.debug("Database authorized user access granted")
            return True

        token_result = await db.token_col.find_one(
            {"user_id": user_id, "expires_at": {"$gt": current_time}, "activated": True},
            {"_id": 1}
        )
        access_granted = bool(token_result)
        logger.debug(f"Token validation {'SUCCESS' if access_granted else 'FAILURE'} for user: {user_id}")
        return access_granted
    except Exception as e:
        logger.error(f"Error in check for user {user_id}: {e}", exc_info=True)
        raise

# NOTE: The 'generate' function (for automatic token generation) is REMOVED
# OR, it should be changed to only generate if called by owner logic. 
# For now, we assume it's only called by an owner command. 
# If it's being called elsewhere for new users, that call needs to be removed.
# मैं 'generate' फ़ंक्शन को यहाँ से हटा रहा हूँ, और मान रहा हूँ कि token अब सिर्फ़ manually generate होगा।

async def manual_generate(user_id: int) -> str:
    """Owner/Admin only - creates a token for a user."""
    try:
        logger.debug(f"Manual token generation started for user: {user_id}")
        existing_token_doc = await db.token_col.find_one(
            {"user_id": user_id, "activated": False, "expires_at": {"$gt": datetime.utcnow()}},
            {"token": 1}
        )
        if existing_token_doc:
            logger.debug(f"Returning existing unactivated token for user: {user_id}")
            return existing_token_doc["token"]
        
        token_str = secrets.token_urlsafe(32)
        masked_token = f"{token_str[:4]}...{token_str[-4:]}"
        logger.debug(f"Generated new token: {masked_token}")
        
        max_retries = 3
        base_delay = 0.5
        for attempt in range(max_retries):
            try:
                ttl_hours = getattr(Var, "TOKEN_TTL_HOURS", 24)
                created_at = datetime.utcnow()
                expires_at = created_at + timedelta(hours=ttl_hours)
                await db.save_main_token(
                    user_id=user_id,
                    token_value=token_str,
                    expires_at=expires_at,
                    created_at=created_at,
                    activated=False
                )
                logger.debug(f"New token generated and saved successfully for user: {user_id}")
                return token_str
            except pyrogram.errors.RPCError as e:
                logger.error(f"Telegram API error while generating new token for user {user_id}: {e}", exc_info=True)
                raise
            except Exception as e:
                if attempt < max_retries - 1:
                    delay = base_delay * (2 ** attempt) + random.uniform(0, 0.1)
                    logger.warning(f"Database error (attempt {attempt+1}/{max_retries}) while saving new token: {e}. Retrying in {delay:.2f} seconds.", exc_info=True)
                    await asyncio.sleep(delay)
                else:
                    logger.error(f"Failed to generate and save new token for user {user_id} after {max_retries} attempts: {e}", exc_info=True)
                    raise
        return ""
    except Exception as e:
        logger.error(f"Error in manual_generate for user {user_id}: {e}", exc_info=True)
        raise

async def allowed(user_id: int) -> bool:
# ... (rest of the functions remain the same: allowed, authorize, deauthorize, get_user, list_allowed, list_tokens, cleanup_expired_tokens) ...
