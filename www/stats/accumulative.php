<?php

/**
 * Here we return metrics which we keep a history of it accepts parameters to return the accumulated value of period
 * Param: start_month (year-month | null ) i.e. 2020-12, don't send to get just one month before end_month Param:
 * end_month (year-month | current | last ) i.e. 2021-03, don't send to get last completed month (same as sending
 * 'last'). Send 'current' to get a partial result for ongoing month
 */

const STATS_DIR = '/var/log/clave/stats2';

$start_month = null;
$end_month = 'last';

if (isset($_REQUEST['start_month'])) {
    $start_month = $_REQUEST['start_month'];
}
if (isset($_REQUEST['end_month'])) {
    $end_month = $_REQUEST['end_month'];
}



if ($end_month === 'last') {
    $end_month = date('Y-m', strtotime('last month'));
}
if ($end_month === 'current') {
    $end_month = date('Y-m', strtotime('this month'));
}

if ($start_month === null) {
    $start_month = $end_month;
}
if ($start_month !== null) {
    if (! strtotime($start_month)) {
        header($_SERVER['SERVER_PROTOCOL'] . ' 400 start_month bad syntax');
        die(0);
    }
}

if (! strtotime($end_month)) {
    header($_SERVER['SERVER_PROTOCOL'] . ' 400 end_month bad syntax');
    die(0);
}


$year_ini = date_parse($start_month)['year'];
$month_ini = date_parse($start_month)['month'];

$year_end = date_parse($end_month)['year'];
$month_end = date_parse($end_month)['month'];



$total_requests = 0;
$total_responses = 0;
$saml_requests = 0;
$eidas_requests = 0;
$stork_requests = 0;

for ($year = $year_ini; $year <= $year_end; $year++) {
    $firstmonth = 1;
    $lastmonth = 12;
    if ($year === $year_ini) {
        $firstmonth = $month_ini;
    }
    if ($year === $year_ini) {
        $lastmonth = $month_end;
    }

    for ($month = $firstmonth; $month <= $lastmonth; $month++) {
        $first_day = 1;
        $last_day = cal_days_in_month(CAL_GREGORIAN, $month, $year);

        for ($day = $first_day; $day <= $last_day; $day++) {
            $timestamp = strtotime("${year}-${month}-${day}");
            if ($timestamp === false) {
                header($_SERVER['SERVER_PROTOCOL'] . ' 400 bad date syntax');
                die(0);
            }
            $date_string = date('Y-m-d', $timestamp);

            $filepath = STATS_DIR . '/' . $date_string . '.log';

            if ($day === $first_day) {
                if (! file_exists($filepath)) {
                    header($_SERVER['SERVER_PROTOCOL'] . ' 400 end_month bad syntax');
                    die(0);
                }
            }

            $daylog = file($filepath, FILE_IGNORE_NEW_LINES);

            foreach ($daylog as $entrystr) {
                $entry = json_decode(preg_replace('!^.*?({)!', '$1', $entrystr));


                if ($entry->op === 'saml:idp:AuthnRequest' ||
                    $entry->op === 'clave:idp:AuthnRequest') {
                    $total_requests++;
                    if ($entry->protocol === 'saml2') {
                        $saml_requests++;
                    } elseif ($entry->protocol === 'saml2-eidas') {
                        $eidas_requests++;
                    } elseif ($entry->protocol === 'saml2-stork') {
                        $stork_requests++;
                    }
                } elseif ($entry->op === 'clave:sp:Response') {
                    $total_responses++;
                }
            }
        }
    }
}


header('Content-type: text/csv');
header(
    "Content-disposition: attachment; filename = stats_clave_usage_${year_ini}-${month_ini}_${year_end}-${month_end}.csv"
);


echo "total_requests, ${total_requests}\n";

echo "total_responses, ${total_responses}\n";

echo "saml_requests, ${saml_requests}\n";

echo "eidas_requests, ${eidas_requests}\n";

echo "stork_requests, ${stork_requests}\n";
