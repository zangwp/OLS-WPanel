<?php
$source=file_get_contents(__DIR__.'/../../internal/executor/assets/wp-inventory-runner/inventory.php');
$start=strpos($source,'function ols_wpanel_inventory_retire_optimizer(): void');
$end=strpos($source,"\n\$token =",$start);
if ($start===false || $end===false) throw new Exception('missing retirement operation');
eval(substr($source,$start,$end-$start));
$multi=false; $reject=false; $cleared=[];
$options=['active_plugins'=>['litespeed-cache/litespeed-cache.php','ols-wpanel-optimizer/ols-wpanel-optimizer.php','other/plugin.php'],'litespeed.conf'=>['cache'=>true],'olsw_optimizer_memory_limit'=>'256M'];
function is_multisite(){return $GLOBALS['multi'];}
function get_option($key,$default){return $GLOBALS['options'][$key] ?? $default;}
function update_option($key,$value){if (!$GLOBALS['reject']) $GLOBALS['options'][$key]=$value;}
function wp_clear_scheduled_hook($hook){$GLOBALS['cleared'][]=$hook;}
function check($ok){if (!$ok) throw new Exception('retirement contract failed');}
ols_wpanel_inventory_retire_optimizer();
check($options['active_plugins']===['litespeed-cache/litespeed-cache.php','other/plugin.php']);
check($options['litespeed.conf']===['cache'=>true] && $options['olsw_optimizer_memory_limit']==='256M');
check($cleared===['olsw_optimizer_preload_batch']);
ols_wpanel_inventory_retire_optimizer();
$options['active_plugins'][]='ols-wpanel-optimizer/ols-wpanel-optimizer.php'; $reject=true;
try{ols_wpanel_inventory_retire_optimizer();throw new Exception('failed update not detected');}catch(RuntimeException $e){check($e->getMessage()==='optimizer_deactivation_failed');}
$multi=true;
try{ols_wpanel_inventory_retire_optimizer();throw new Exception('multisite not rejected');}catch(RuntimeException $e){check($e->getMessage()==='multisite_unsupported');}
echo "retirement checks passed\n";
