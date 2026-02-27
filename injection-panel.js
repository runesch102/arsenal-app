// InjectionPanel React component (createElement form, no JSX)
// Injected into frontend via css-hook.js

function InjectionPanel(){
var _s=useState,_ce=React.createElement;
var _d=_s([]),devices=_d[0],setDevices=_d[1];
var _t=_s([]),templates=_t[0],setTemplates=_t[1];
var _sd=_s(''),selDev=_sd[0],setSelDev=_sd[1];
var _st=_s(''),selTpl=_st[0],setSelTpl=_st[1];
var _state=_s('ready'),state=_state[0],setState=_state[1];
var _prog=_s(0),progress=_prog[0],setProgress=_prog[1];
var _res=_s(null),result=_res[0],setResult=_res[1];
var _err=_s(''),error=_err[0],setError=_err[1];
var pollRef=useRef(null);

useEffect(function(){
  api('/api/devices').then(function(d){
    if(Array.isArray(d))setDevices(d);
    else if(d&&d.devices)setDevices(d.devices);
  });
  api('/api/payload-templates').then(function(t){
    if(Array.isArray(t))setTemplates(t);
    else if(t&&t.templates)setTemplates(t.templates);
  });
  return function(){if(pollRef.current)clearInterval(pollRef.current);};
},[]);

function startInject(){
  if(!selDev||!selTpl)return;
  setState('injecting');setProgress(0);setError('');setResult(null);
  api('/api/inject',{method:'POST',body:JSON.stringify({device_id:parseInt(selDev),template_id:selTpl})})
  .then(function(r){
    if(r.error){setState('error');setError(r.error);return;}
    var jobId=r.id||r.job_id;
    if(!jobId){setState('done');setResult(r);return;}
    var p=10;
    pollRef.current=setInterval(function(){
      p=Math.min(p+5,95);setProgress(p);
      api('/api/inject/jobs/'+jobId).then(function(s){
        if(s.status==='completed'||s.status==='done'){
          clearInterval(pollRef.current);setProgress(100);setState('done');setResult(s);
        }else if(s.status==='failed'||s.status==='error'){
          clearInterval(pollRef.current);setState('error');setError(s.error||'Fejl');
        }
      });
    },2000);
  }).catch(function(e){setState('error');setError(e.message);});
}

function reset(){setState('ready');setProgress(0);setResult(null);setError('');}

var selDevObj=devices.find(function(d){return String(d.id)===selDev;});
var selTplObj=templates.find(function(t){return t.id===selTpl;});

return _ce('div',{style:{padding:16}},
  _ce('h3',{style:{margin:'0 0 16px',fontSize:16,color:'var(--text)'}},'\uD83D\uDC89 Payload Injection'),

  state==='ready'&&_ce('div',null,
    _ce('div',{style:{marginBottom:12}},
      _ce('label',{style:{display:'block',fontSize:11,color:'var(--text3)',marginBottom:4}},'Target Device'),
      _ce('select',{value:selDev,onChange:function(e){setSelDev(e.target.value);},
        style:{width:'100%',padding:'8px 12px',background:'var(--bg2)',border:'1px solid var(--border)',borderRadius:8,color:'var(--text)',fontSize:13}},
        _ce('option',{value:''},'-- V\u00e6lg device --'),
        devices.map(function(d){return _ce('option',{key:d.id,value:d.id},d.name+' ('+d.type+')'+(d.status==='online'?' \u2705':' \u26AA'));})
      )
    ),
    selDevObj&&_ce('div',{style:{fontSize:10,color:'var(--text3)',marginBottom:12,padding:8,background:'var(--bg)',borderRadius:6}},
      '\uD83D\uDCE1 ',selDevObj.name,' | ',selDevObj.type,' | ',selDevObj.vpn_ip||'no VPN',' | ',selDevObj.status
    ),
    _ce('div',{style:{marginBottom:12}},
      _ce('label',{style:{display:'block',fontSize:11,color:'var(--text3)',marginBottom:4}},'Payload Template'),
      _ce('select',{value:selTpl,onChange:function(e){setSelTpl(e.target.value);},
        style:{width:'100%',padding:'8px 12px',background:'var(--bg2)',border:'1px solid var(--border)',borderRadius:8,color:'var(--text)',fontSize:13}},
        _ce('option',{value:''},'-- V\u00e6lg template --'),
        templates.map(function(t){return _ce('option',{key:t.id,value:t.id},t.name+(t.risk?' (\u26A0 '+t.risk+')':''));})
      )
    ),
    selTplObj&&_ce('div',{style:{fontSize:10,color:'var(--text3)',marginBottom:12,padding:8,background:'var(--bg)',borderRadius:6}},
      '\uD83D\uDCC4 ',selTplObj.name,' | Risk: ',selTplObj.risk||'?',' | OS: ',selTplObj.os||'?',' | Time: ',selTplObj.time||'?'
    ),
    _ce('button',{
      disabled:!selDev||!selTpl,
      onClick:startInject,
      style:{width:'100%',padding:'12px',fontSize:14,fontWeight:600,background:(!selDev||!selTpl)?'var(--border)':'var(--accent)',color:(!selDev||!selTpl)?'var(--text3)':'#000',borderRadius:8,border:'none',cursor:(!selDev||!selTpl)?'not-allowed':'pointer'}
    },'\uD83D\uDE80 Start Injection')
  ),

  state==='injecting'&&_ce('div',{style:{textAlign:'center',padding:'40px 0'}},
    _ce('div',{style:{fontSize:40,marginBottom:16}},'\u23F3'),
    _ce('div',{style:{fontSize:14,fontWeight:600,color:'var(--text)',marginBottom:8}},'Injecting payload...'),
    _ce('div',{style:{fontSize:11,color:'var(--text3)',marginBottom:16}},
      selTplObj?selTplObj.name:'template',' \u2192 ',selDevObj?selDevObj.name:'device'
    ),
    _ce('div',{style:{width:'100%',height:8,background:'var(--bg2)',borderRadius:4,overflow:'hidden'}},
      _ce('div',{style:{width:progress+'%',height:'100%',background:'var(--accent)',borderRadius:4,transition:'width 0.3s'}})
    ),
    _ce('div',{style:{fontSize:10,color:'var(--text3)',marginTop:8}},progress+'%')
  ),

  state==='done'&&_ce('div',{style:{textAlign:'center',padding:'40px 0'}},
    _ce('div',{style:{fontSize:40,marginBottom:16}},'\u2705'),
    _ce('div',{style:{fontSize:14,fontWeight:600,color:'#10b981',marginBottom:8}},'Injection Complete!'),
    result&&_ce('pre',{style:{textAlign:'left',fontSize:10,padding:12,background:'var(--bg)',borderRadius:8,maxHeight:200,overflow:'auto',color:'var(--text3)'}},JSON.stringify(result,null,2)),
    _ce('button',{onClick:reset,style:{marginTop:16,padding:'8px 24px',background:'var(--accent)',color:'#000',border:'none',borderRadius:8,cursor:'pointer',fontWeight:600}},'Ny Injection')
  ),

  state==='error'&&_ce('div',{style:{textAlign:'center',padding:'40px 0'}},
    _ce('div',{style:{fontSize:40,marginBottom:16}},'\u274C'),
    _ce('div',{style:{fontSize:14,fontWeight:600,color:'#ef4444',marginBottom:8}},'Injection Fejl'),
    _ce('div',{style:{fontSize:12,color:'var(--text3)',marginBottom:16,padding:12,background:'var(--bg)',borderRadius:8}},error),
    _ce('button',{onClick:reset,style:{marginTop:8,padding:'8px 24px',background:'var(--accent)',color:'#000',border:'none',borderRadius:8,cursor:'pointer',fontWeight:600}},'Pr\u00f8v Igen')
  )
);
}

function ArsenalWithInject(){
var _m=useState('arsenal'),mode=_m[0],setMode=_m[1];
var _ce=React.createElement;
return _ce('div',null,
  _ce('div',{style:{display:'flex',gap:8,marginBottom:12,padding:'0 12px'}},
    _ce('button',{
      onClick:function(){setMode('arsenal');},
      style:{padding:'6px 16px',fontSize:12,fontWeight:600,borderRadius:6,border:'1px solid var(--border)',cursor:'pointer',background:mode==='arsenal'?'var(--accent)':'var(--bg2)',color:mode==='arsenal'?'#000':'var(--text3)'}
    },'\u2694\uFE0F Arsenal'),
    _ce('button',{
      onClick:function(){setMode('inject');},
      style:{padding:'6px 16px',fontSize:12,fontWeight:600,borderRadius:6,border:'1px solid var(--border)',cursor:'pointer',background:mode==='inject'?'var(--accent)':'var(--bg2)',color:mode==='inject'?'#000':'var(--text3)'}
    },'\uD83D\uDC89 Injection')
  ),
  mode==='arsenal'?_ce(ArsenalExecTab,null):_ce(InjectionPanel,null)
);
}
