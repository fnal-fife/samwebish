. $SPACK_ROOT/setup-env.sh
spack env activate samwebish

export SAM_WEB_BASE_URL=http://localhost:8000/sam/hypot/api
export IFDH_BASE_URI=http://localhost:8000/sam/hypot/api
export SAM_EXPERIMENT=hypot

htgettoken 
