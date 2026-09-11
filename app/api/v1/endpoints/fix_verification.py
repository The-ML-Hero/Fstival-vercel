from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import ProjectNotFoundError, TargetNotAuthorizedError
from app.db.session import get_db
from app.schemas.module3.verification import FixVerificationRequest, FixVerificationResponse
from app.services.fix_verifier import FixVerifier

router = APIRouter(prefix="/findings", tags=["Fix Verification"])


@router.post("/{finding_id}/verify-fix", response_model=FixVerificationResponse)
async def verify_vulnerability_fix(
    finding_id: str,
    payload: Optional[FixVerificationRequest] = None,
    db: AsyncSession = Depends(get_db)
):
    """
    Reruns the original security attack test against the target API to verify if the vulnerability is FIXED.
    Compares before and after status codes and updates verification state.
    """
    verifier = FixVerifier(db)
    override_url = payload.override_base_url if payload else None
    try:
        verification_res = await verifier.verify_fix(finding_id, override_base_url=override_url)
        return verification_res
    except ProjectNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except TargetNotAuthorizedError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Fix verification failed: {str(e)}")
