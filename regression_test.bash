#!/bin/bash

start_server() {
    (
      . ./testdata/setup.sh
      nginx -p $PWD -e logs/nginx_error_log -c testdata/nginx.conf
      fastapi dev --entrypoint samwebish:app > logs/fastapi_dev.log &
      echo $! > logs/server.pid
    )

    sleep 1
    if kill -0 $(<logs/server.pid)
    then
        succeeded fastapi dev --entrypoint samwebish:app 
    else
        failed fastapi dev --entrypoint samwebish:app 
        exit
    fi
    trap "kill $(<logs/server.pid) $(<logs/nginx.pid) || true;  rm logs/server.pid" 0 1 2 3 4 5 6 7 8

    sleep 1
    # let server wake up...
}

. ./testdata/setup_client.sh

verbose_check() {
   if [ "$1" = "-v" ] 
   then 
      verbose=true
   else
      verbose=false
   fi
}
succeeded() {
   if $verbose
   then
       echo "Succeeded: $*"
   else
       printf "."
   fi
}

fail_list=""
failed() {
   if $verbose
   then
       echo "Failed: $*"
   else
       printf "F"
   fi
   fail_list="${fail_list}\nFailed $*"
}

run_expecting()  {

   if [ "$1" = "-f" ]
   then
       expect_fail=true
       expect_success=false
       shift
   else
       expect_fail=false
       expect_success=true
   fi

   cmd="$1"
   shift
   fc=0
   out=$(eval "$cmd" 2>&1)
   ec=$?

   if $expect_fail && [ $ec = 0 ]
   then
       failed "$cmd exitcode $ec"
       return
   fi
   if $expect_success && [ $ec != 0 ]
   then
       failed "$cmd exitcode $ec"
       return 1
   fi
   for pat in "$@"
   do
       if echo "$out" | grep "$pat" > /dev/null 
       then 
           :
       else
           failed "$cmd $pat"
           fc=$((fc + 1))
       fi
   done
   if [ "$fc" == "0" ]
   then 
       succeeded "$cmd"
   fi
   return $ec
}

finish_up() {
    printf "$fail_list"
    echo
    [ "" = "$fail_list" ]
}

make_new_file_metadata() {
    ds=$(date "+%Y%m%d%H%M%S")
    sed -e "s/@DATESTAMP@/$ds/" \
       < testdata/md_new_file_template.json \
       > testdata/md_new_file.json
}

# =-=-=-=-=-=-=-=-=-=-=-=-=-=-

verbose_check "$@"

start_server

run_expecting "samweb locate-file a.fcl" "FNAL_DCACHE_DISK_TEST" "/pnfs/fnal.gov/" "a.fcl"
run_expecting "samweb list-definitions" "tst_q_1710507530" "tst_q_1710508175"
run_expecting "samweb describe-definition tst_q_1710508175" "Definition Name: tst_q_1710508175" "Dimensions: files from mengel:tst1710508175"
run_expecting "samweb count-definition-files tst_q_1710508175" "4"
run_expecting "samweb list-definition-files --summary tst_q_1788293412.8690157" "File count:" "25" "Total size:" "906"
run_expecting "samweb list-files defname:gen_cfg" "c.fcl" "d.fcl"
run_expecting "samweb list-files --summary defname:gen_cfg" "File count:" "5" "Total size:" "100"
run_expecting "samweb get-metadata b.fcl" "file_size:" "20"
run_expecting "samweb get-metadata --json b.fcl" '"file_size":' "20" "{" 

make_new_file_metadata
run_expecting "samweb declare-file testdata/md_new_file.json" 

run_expecting -f "samweb declare-file testdata/md_file_exists.json" "already exists"
run_expecting -f "samweb declare-file testdata/md_bad_checksum.json"  "checksum md5: value is wrong length" 
run_expecting "samweb run-project --user=mengel --defname=gen_cfg 'echo doing %fileurl...'" "Started project" "Started consumer processs ID" "doing" "a.fcl" "d.fcl" "Stopped project"

finish_up
