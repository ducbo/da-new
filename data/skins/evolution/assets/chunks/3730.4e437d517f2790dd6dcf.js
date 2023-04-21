"use strict";(self.webpackChunk=self.webpackChunk||[]).push([[3730],{"./js/api/commands/converters/customItems.ts":function(_,m,r){r.d(m,{CR:function(){return f}});var s=r("../node_modules/ramda/es/index.js"),u=r("./js/api/commands/converters/index.ts"),l=r("./js/api/commands/utils/transduce.ts"),p=r("./js/api/commands/converters/toSelectData.ts");const f=a=>{const i={name:a.name,type:a.type==="listbox"?"select":a.type,label:a.string,description:a.desc||"",value:a.type==="checkbox"?(0,u.sw)(a.checked||"no"):a.value||""};return i.type==="select"?s.BPw(i,(0,p.M1)(a.select||{})):i},x=a=>(0,l.vr)([(0,l.uD)(i=>/^item\d+val$/.test(i)),(0,l.r5)(i=>{const c=i,n=i.replace("val","txt"),e=a[c],t=a[n];return{[e]:t}})],Object.keys(a)),y=(a,i)=>s.qCK(n=>{const e={name:n.name,type:n.type==="listbox"?"select":n.type,description:n.desc||"",value:n.value||"",label:n.string};return n.type==="listbox"?(e.value=n.default,e.options=x(n)):n.type==="checkbox"&&(e.value=n.checked==="yes"),e},s.BPw({name:a}),(0,l.vr)([(0,l.r5)(n=>{const[e,t]=s.Vl2("=",n);return{[e]:t}})]),s.Vl2("&"))(i);m.ZP={fromObject:f,fromString:y}},"./js/api/commands/converters/index.ts":function(_,m,r){r.d(m,{l$:function(){return c.ZP},t0:function(){return s.t0},S8:function(){return s.S8},ql:function(){return s.ql},sw:function(){return s.sw},Qu:function(){return s.Qu},He:function(){return s.He},M1:function(){return i.M1},sf:function(){return e},cc:function(){return a}});var s=r("./js/api/commands/converters/primitive.ts"),u=r("../node_modules/monet/dist/monet.js"),l=r("./js/api/commands/types.ts");const p=t=>typeof t=="object"?u.Either.Right(t):u.Either.Left(new Error("Passed param is not an object")),f=t=>typeof t.usage=="string"?u.Either.Right(t):u.Either.Left(new Error("usage property is required")),x=t=>({usage:(0,s.He)(t.usage),limit:(0,s.Qu)(t.limit)}),y=({usage:t,limit:o})=>{let v=l.H.Normal;const O=Math.floor(t/o*100);return O>=100?v=l.H.OverUsed:O>80&&(v=l.H.AlmostUsed),{usage:t,limit:o,status:v}},a=t=>{const o=u.Either.Right(t).flatMap(p).flatMap(f).map(x).map(y);if(o.isLeft())throw o.left();return o.right()};var i=r("./js/api/commands/converters/toSelectData.ts"),c=r("./js/api/commands/converters/customItems.ts"),n=r("../node_modules/ramda/es/index.js");const e=t=>o=>{const{info:v}=o,O=n.CEd(["info"],o);return{columns:v.columns,rowsCount:Number(v.rows),rows:n.UID(t,n.VO0(O))}}},"./js/api/commands/converters/toSelectData.ts":function(_,m,r){r.d(m,{M1:function(){return y}});var s=r("../node_modules/monet/dist/monet.js"),u=r.n(s),l=r("./js/api/commands/utils/transduce.ts"),p=r("../node_modules/ramda/es/index.js");const f=a=>s.Maybe.Some(a).flatMap(i=>{const c=i.find(n=>n.selected==="yes");return c?s.Maybe.Some(c):s.Maybe.None()}).flatMap(i=>s.Maybe.fromNull(i.value)).orSome(""),x=(0,l.vr)([(0,l.r5)(a=>({[a.value]:a.text}))]),y=a=>{const i=(0,p.VO0)(a);return{value:f(i),options:x(i)}}},"./js/api/commands/types.ts":function(_,m,r){r.d(m,{H:function(){return s}});var s;(function(u){u.Normal="normal",u.AlmostUsed="almost_used",u.OverUsed="overused"})(s||(s={}))},"./js/api/commands/user/ssh-keys/index.ts":function(_,m,r){r.d(m,{D1:function(){return O},Tl:function(){return v},w:function(){return D},v:function(){return M},RR:function(){return o},fX:function(){return C},lY:function(){return P}});var s=r("./js/api/command/index.js"),u=r("../node_modules/ramda/es/index.js"),l=r("./js/api/commands/converters/index.ts"),p=r("../node_modules/monet/dist/monet.js"),f;(function(d){d.VALUE="value",d.CHECKBOX="checkbox"})(f||(f={}));const x=d=>p.Maybe.Some(d).flatMap(h=>p.Maybe.fromNull(h.users)).orSome([]),y=u.zGw(u.vgT("keysize"),l.M1),a=(d,h)=>({id:d,...h,timestamp:(0,l.t0)(h.timestamp)}),i=d=>u.Zpf(d.public_keys).map(u.nnj(a)),c=d=>h=>{const E=p.Maybe.Some(h).flatMap(g=>p.Maybe.fromNull(g.options)).map(u.yAE({})).map(u.VO0).map(u.u4g((g,{name:K,value:R})=>({...g,[K]:R||!0}),{})).orSome({}),b=p.Maybe.Some(d).flatMap(g=>p.Maybe.fromNull(g.global_keys)).flatMap(g=>p.Maybe.fromNull(g[h.fingerprint])),S=b.map(g=>g.who).orSome("no"),k=b.flatMap(g=>p.Maybe.fromNull(g.users)).map(u.Zpf).map(u.hXT(u.zGw(u.hL$(1),u.vgT("enabled"),u.fS0("yes")))).map(u.UID(u.YMb)).orSome([]);return{...h,options:E,global:S,users:S==="except"?u.zud(k,d.users||[]):k}},n=d=>u.VO0(d.authorized_keys).map(c(d));var e={getKeys:{users:x,options:u.vgT("key_options"),sizes:y,public:i,authorized:n}};const t="/CMD_SSH_KEYS",o=s.Z.get({id:"SSH_KEYS",url:t,mapResponse:e.getKeys,schema:{enabled_users:s.Z.OPTIONAL_BOOL,fingerprint:s.Z.OPTIONAL_STRING}}),v=s.Z.post({url:t,params:{action:"create",type:"rsa"},schema:{id:s.Z.REQUIRED_STRING,comment:s.Z.REQUIRED_STRING,keysize:s.Z.REQUIRED_STRING,passwd:s.Z.OPTIONAL_STRING,overwrite:s.Z.REQUIRED_BOOL,authorize:s.Z.REQUIRED_BOOL},before:({passwd:d})=>({passwd2:d})}),O=s.Z.select({url:t,params:{type:"public",authorize:!0}}),M=s.Z.select({url:t,params:{type:"public",delete:!0}}),D=s.Z.select({url:t,params:{type:"authorized_keys",delete:!0}}),P=s.Z.post({url:t,params:{type:"paste",action:"authorize"},schema:{text:s.Z.REQUIRED_STRING}}),C=s.Z.post({url:"/CMD_SSH_KEYS",params:{action:"modify"},schema:{fingerprint:s.Z.REQUIRED_STRING,comment:s.Z.REQUIRED_STRING,options:{type:Object,required:!0,default:()=>({})},global:s.Z.REQUIRED_BOOL,users:{type:Array,required:!0,default:()=>[]},who:s.Z.OPTIONAL_STRING},before:({options:d,users:h,global:E})=>({...d,global_key:E,select:h,options:null,global:null,users:null})})},"./js/api/commands/utils/transduce.ts":function(_,m,r){r.d(m,{Re:function(){return p},r5:function(){return u},uD:function(){return l},vr:function(){return i},zh:function(){return y}});var s=r("../node_modules/ramda/es/index.js");const u=c=>n=>(e,t)=>{const o=c(t);return n(e,o)},l=c=>n=>(e,t)=>c(t)?n(e,t):e,p=(c,n)=>(c.push(n),c),f=(c,n)=>s.BPw(c,n),x=(c,n,e,t)=>{const o=s.qCK(...e);return t.reduce(o(n),c)},y=s.WAo(x),a=y([],p),i=y({},f)},"./js/pages/user/ssh-keys/edit.vue":function(_,m,r){r.r(m),r.d(m,{default:function(){return c}});var s=function(){var e=this,t=e._self._c;return t("app-page",{scopedSlots:e._u([{key:"default",fn:function(){return[t("app-page-section",{scopedSlots:e._u([{key:"section:title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("Key Data"))}})]},proxy:!0}])},[e._v(" "),t("ui-form-element",{attrs:{group:"editKey",validators:{required:!0}},scopedSlots:e._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("Comment"))}})]},proxy:!0},{key:"content",fn:function(){return[t("input-text",{model:{value:e.comment,callback:function(o){e.comment=o},expression:"comment"}})]},proxy:!0}])}),e._v(" "),t("ui-form-element",{scopedSlots:e._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("Fingerprint"))}})]},proxy:!0},{key:"content",fn:function(){return[t("input-text",{attrs:{disabled:"",value:e.fingerprint}})]},proxy:!0}])}),e._v(" "),t("ui-form-element",{scopedSlots:e._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("Type"))}})]},proxy:!0},{key:"content",fn:function(){return[t("input-text",{attrs:{disabled:"",value:e.key.type}})]},proxy:!0}])}),e._v(" "),t("ui-form-element",{attrs:{underline:!1},scopedSlots:e._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("Size"))}})]},proxy:!0},{key:"content",fn:function(){return[t("input-text",{attrs:{disabled:"",value:e.key.keysize}})]},proxy:!0}])})],1),e._v(" "),t("app-page-section",{scopedSlots:e._u([{key:"section:title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("Key Options"))}})]},proxy:!0}])},[e._v(" "),e._l(e.options,function(o){return t("ui-form-element",{key:o.name,scopedSlots:e._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:e._s(o.name)}})]},proxy:!0},{key:"content",fn:function(){return[o.type==="value"?t("input-text",{model:{value:o.value,callback:function(v){e.$set(o,"value",v)},expression:"option.value"}}):o.type==="checkbox"?t("input-checkbox",{model:{value:o.value,callback:function(v){e.$set(o,"value",v)},expression:"option.value"}}):e._e()]},proxy:!0}],null,!0)})}),e._v(" "),e.possibleOptions.length?t("ui-form-element",{scopedSlots:e._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("Add Option"))}})]},proxy:!0},{key:"content",fn:function(){return[t("input-select-legacy",{attrs:{options:e.possibleOptions},on:{change:function(o){return e.addOption(o)}}})]},proxy:!0}],null,!1,135100710)}):e._e(),e._v(" "),e.showGlobal?t("ui-form-element",{attrs:{underline:!1},scopedSlots:e._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("Global Key"))}})]},proxy:!0},{key:"content",fn:function(){return[t("input-checkbox",{model:{value:e.global,callback:function(o){e.global=o},expression:"global"}})]},proxy:!0}],null,!1,414376362)}):e._e()],2),e._v(" "),e.showGlobal&&e.global?t("app-page-section",{scopedSlots:e._u([{key:"section:title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("Global Key Options"))}})]},proxy:!0}],null,!1,2430914280)},[e._v(" "),t("ui-form-element",{attrs:{underline:!1},scopedSlots:e._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("Apply To"))}})]},proxy:!0},{key:"content",fn:function(){return[t("ui-grid",[t("input-radio",{attrs:{value:"all"},model:{value:e.who,callback:function(o){e.who=o},expression:"who"}},[t("span",{domProps:{textContent:e._s(e.$gettext("All Users"))}})]),e._v(" "),t("input-radio",{attrs:{value:"except"},model:{value:e.who,callback:function(o){e.who=o},expression:"who"}},[t("span",{domProps:{textContent:e._s(e.$gettext("All Users Except Selected Users"))}})]),e._v(" "),t("input-radio",{attrs:{value:"selected"},model:{value:e.who,callback:function(o){e.who=o},expression:"who"}},[t("span",{domProps:{textContent:e._s(e.$gettext("Selected Users"))}})])],1)]},proxy:!0}],null,!1,3177109262)}),e._v(" "),t("transition",{attrs:{name:"fade"}},[e.who!=="all"?t("ui-form-element",{attrs:{underline:!1},scopedSlots:e._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("Users"))}})]},proxy:!0},{key:"content",fn:function(){return[t("input-select-multiple",{attrs:{options:e.$api.keys.users},model:{value:e.users,callback:function(o){e.users=o},expression:"users"}})]},proxy:!0}],null,!1,1331415931)}):e._e()],1)],1):e._e()]},proxy:!0},{key:"footer:buttons",fn:function(){return[t("ui-button",{attrs:{theme:"safe",size:"big","validate-group":"editKey"},on:{click:e.modifyKey}},[t("span",{domProps:{textContent:e._s(e.$gettext("Save"))}})])]},proxy:!0}])})},u=[],l=r("../node_modules/ramda/es/index.js"),p=r("./js/api/commands/user/ssh-keys/index.ts"),f=r("./js/api/commands/utils/transduce.ts"),x={preload:({fingerprint:n})=>(0,p.RR)({fingerprint:n,enabled_users:!0}),api:[{command:p.RR,bind:"keys"}],props:{fingerprint:{type:String,required:!0,default:""}},data:()=>({comment:"",options:[],global:!1,who:"all",users:[]}),computed:{showGlobal(){return this.$_useStore("user").hasRole("reseller")},key(){return this.$api.keys.authorized.find(n=>n.fingerprint===this.fingerprint)},isOptionDefined(){return n=>!!this.options.find(({name:e})=>e===n.value)},possibleOptions(){return l.zGw(l.Zpf,l.UID(l._Qy(["value","type"])),l.hXT(l.CyQ(this.isOptionDefined)))(this.$api.keys.options)},mergedOptions(){return(0,f.vr)([(0,f.uD)(n=>n.value!==!1),(0,f.r5)(n=>({[n.name]:n.value}))],this.options)},requestData(){return{comment:this.comment,fingerprint:this.fingerprint,options:this.mergedOptions,global:this.global,users:this.users,who:this.who}}},created(){this.comment=this.key.comment,this.options=Object.entries(this.key.options).map(([n,e])=>({name:n,value:e,type:this.getOptionType(n)})),this.global=this.key.global!=="no",this.global&&(this.who=this.key.global),this.users=this.key.users},methods:{addOption(n){this.options.push({type:n.type,name:n.value,value:n.type==="value"?"":!1})},getOptionType(n){return(this.possibleOptions.find(({value:t})=>t===n)||{}).type||"value"},modifyKey(){(0,p.fX)(this.requestData).then(this.removeEmptyOptions)},removeEmptyOptions(){this.options=this.options.filter(n=>n.value)}}},y=x,a=r("../node_modules/vue-loader/lib/runtime/componentNormalizer.js"),i=(0,a.Z)(y,s,u,!1,null,null,null),c=i.exports}}]);
