. $SPACK_ROOT/setup-env.sh

spack load --first sam-web-client@3.6

export SAM_WEB_BASE_URL=http://localhost:8000/sam/hypot/api
export IFDH_BASE_URI=http://localhost:8000/sam/hypot/api
export SAM_EXPERIMENT=hypot

htgettoken 
