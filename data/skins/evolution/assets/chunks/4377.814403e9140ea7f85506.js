(self.webpackChunk=self.webpackChunk||[]).push([[4377],{"./js/api/commands/admin/users/actions.js":function(R,f,l){"use strict";l.d(f,{Ss:function(){return h},Vt:function(){return v},XB:function(){return p},f1:function(){return c},uV:function(){return y},vk:function(){return x}});var s=l("./js/api/command/index.js");const _=s.Z.post({url:"/CMD_SELECT_USERS",notifySuccess:!0,notifyError:!0,params:{location:"CMD_ALL_USER_SHOW"},schema:{select:s.Z.ROWS},blocking:!0}),c=_.extend({params:{dosuspend:!0},schema:{reason:s.Z.REQUIRED_STRING},blocking:!0}),h=_.extend({params:{dounsuspend:!0},blocking:!0}),v=_.extend({params:{delete:!0,confirmed:!0},schema:{leave_dns:s.Z.OPTIONAL_BOOL},blocking:!0}),y=s.Z.post({url:"/CMD_ACCOUNT_ADMIN",params:{action:"create"},schema:{username:s.Z.REQUIRED_STRING,email:s.Z.REQUIRED_STRING,passwd:s.Z.REQUIRED_STRING,passwd2:s.Z.REQUIRED_STRING,notify:s.Z.REQUIRED_BOOL}}),x=s.Z.post({url:"/CMD_COMMENTS",params:{location:"CMD_SHOW_RESELLER"},schema:{user:s.Z.REQUIRED_STRING,comments:s.Z.REQUIRED_STRING}}),p=s.Z.post({url:"/CMD_MOVE_USERS",id:"USERS_COUNT_PER_RESELLER",response:{},after:d=>d.flow(d.getProp("data_list"),d.mapValues(i=>i.length))})},"./js/api/commands/admin/users/resellers.js":function(R,f,l){"use strict";l.d(f,{Rf:function(){return y},Rh:function(){return x},UH:function(){return h},YY:function(){return i},Zg:function(){return d},fy:function(){return v},pw:function(){return p},tr:function(){return c},xn:function(){return _}});var s=l("./js/api/command/index.js");const _=s.Z.post({id:"RESELLER_OPTIONS",url:"/CMD_ACCOUNT_RESELLER",notifySuccess:!1,blocking:!1,after:t=>t.flow(t.moveProp("free_ips","freeIPs"),t.mapProp("freeIPs",t.convert.toAppNumber),t.mapProp("ip_select",t.toSelect))}),c=s.Z.post({url:"/CMD_ACCOUNT_RESELLER",params:{action:"create",add:!0},schema:{username:s.Z.REQUIRED_STRING,email:s.Z.REQUIRED_STRING,passwd:s.Z.REQUIRED_STRING,passwd2:s.Z.REQUIRED_STRING,domain:s.Z.REQUIRED_STRING,package:s.Z.OPTIONAL_STRING,notify:s.Z.REQUIRED_BOOL,ip:s.Z.REQUIRED_STRING}}),h=s.Z.get({id:"RESELLERS",url:"/CMD_RESELLER_SHOW",pagination:!0,params:{bytes:!0},after:t=>t.flow(t.wrap("resellers"),t.moveProp({"resellers.reasons":"reasons"}),t.mapProp("resellers",t.toTable(t.mapArray(a=>{if(typeof a.bandwidth=="string")return{username:a.username,valid:!1};const[r,g]=a.nusers.split("/");return{username:a.username,nusers:r,nuserslimit:t.convert.toAppLimit(g),suspended:a.suspended.value!=="no:",reason:a.suspended.reason||"none",vdomains:t.toLimitedUsage()(a.vdomains),bandwidth:t.toLimitedUsage()(a.bandwidth),quota:t.toLimitedUsage()(a.quota),valid:!0}}))),t.mapProp("reasons",t.toSelect))}),v=s.Z.get({id:"RESELLER_STATS",url:"/CMD_SHOW_RESELLER",params:{bytes:!0},schema:{user:s.Z.REQUIRED_STRING},after:t=>t.flow(t.project({comments:"comments",info:"stats",usage:"stats",stats:"stats",users:"users",deleted_user_bandwidth:"stats",additional_bandwidth:"stats"}),t.mapProps({usage:t.flow(t.deleteProp("info"),t.filter(t.getProp("max_usage")),t.transformObject(({setting:a,usage:r,allocated:g,max_usage:b})=>({[a]:{usage:r,allocated:g,limit:b}})),t.mapValues(t.mapProps({usage:t.convert.toAppNumber,limit:t.convert.toAppLimit,allocated:t.convert.toAppLimit}))),stats:t.flow(t.deleteProp("info"),t.filter(t.flow(t.getProp("usage"),a=>["ON","OFF"].includes(a))),t.transformObject(({setting:a,usage:r})=>({[a]:r})),t.mapValues(t.convert.toAppBoolean)),info:t.flow(t.deleteProp("info"),t.filter(a=>!a.max_usage&&!["ON","OFF"].includes(a.usage)),t.transformObject(({setting:a,usage:r})=>({[a]:r}))),comments:t.flow(t.convert.toAppString,t.convert.toAppText),users:t.toTable(t.mapArrayProps({bandwidth:t.toLimitedUsage(),quota:t.toLimitedUsage(),vdomains:t.toLimitedUsage(),suspended:t.flow(t.isEqual("No"),t.not)})),skinInfo:t.feedWith(1,t.flow(t.project({custom:"is_reseller_skin",path:"reseller_skin",owner:"reseller_skin_owner"}),t.mapProp("custom",t.isEqual("1")))),deleted_user_bandwidth:t.flow(t.deleteProp("info"),Object.values,a=>a.find(({setting:r})=>r==="deleted_user_bandwidth"),a=>typeof a!="undefined"?t.mapProps({usage:t.convert.toAppNumber,limit:t.convert.toAppLimit,allocated:t.convert.toAppLimit})(a):!1),additional_bandwidth:t.flow(t.deleteProp("info"),Object.values,a=>a.find(({setting:r})=>r==="additional_bandwidth")||{usage:!1},a=>a.usage)}))}),y=s.Z.get({id:"RESELLER_USERS",url:"/CMD_SHOW_RESELLER",params:{bytes:!0},pagination:!0,schema:{user:s.Z.REQUIRED_STRING},after:t=>t.flow(t.getProp("users"),t.toTable(t.mapArrayProps({bandwidth:t.toLimitedUsage(),quota:t.toLimitedUsage(),vdomains:t.toLimitedUsage(),suspended:t.flow(t.isEqual("No"),t.not)})))}),x=s.Z.get({id:"RESELLER_DATA",url:"/CMD_MODIFY_RESELLER",params:{bytes:!0},schema:{user:s.Z.REQUIRED_STRING},after:t=>t.flow(a=>({packageData:a,packages:a.packages,package:a.packages,custom:a.custom_items,haveInode:a.have_inode,cgroup:a.cgroup}),t.mapProps({haveInode:t.isEqual("yes"),package:t.flow(t.find(t.getProp("selected")),t.getProp("value")),packages:t.flow(t.transformObject(({value:a,text:r})=>({[a]:r})),t.filter((a,r)=>!!r)),custom:t.flow(t.toArray,t.mapArray(a=>{const r={type:a.type,description:a.desc,label:a.string,name:a.name};switch(a.type){case"checkbox":return Object.assign(r,{value:t.isEqual("yes")(a.checked)});case"text":return Object.assign(r,{value:a.value});case"listbox":return Object.assign(r,{value:t.flow(t.find(t.getProp("selected")),t.getProp("value"))(a.select),options:t.transformObject(({value:g,text:b})=>({[g]:b}))(a.select)});default:return!1}}),t.filter(t.notEmpty)),packageData:t.flow(t.deleteProps(["packages","have_inode","custom_items"]),t.transformObject((a,r)=>{if(a.type==="unlimited"){const g=t.convert.toAppLimit(a.value)===1/0,b=g?"":a.value;return{limits:{[r]:{value:b,unlimited:g}}}}return a.type==="checkbox"?{features:{[r]:a.checked==="yes"}}:{[r]:a}})),cgroup:a=>a?Object.values({...a.options||{},...a.saved||{}}):[]}))}),p=s.Z.post({url:"/CMD_MODIFY_RESELLER",params:{action:"package"},schema:{user:s.Z.REQUIRED_STRING,package:s.Z.REQUIRED_STRING}}),d=s.Z.post({url:"/CMD_MODIFY_RESELLER",params:{action:"customize",bytes:!0},schema:{user:s.Z.REQUIRED_STRING,bandwidth:s.Z.OPTIONAL_STRING,ubandwidth:s.Z.OPTIONAL_BOOL,quota:s.Z.OPTIONAL_STRING,uquota:s.Z.OPTIONAL_BOOL,inode:s.Z.OPTIONAL_STRING,uinode:s.Z.OPTIONAL_BOOL,vdomains:s.Z.OPTIONAL_STRING,uvdomains:s.Z.OPTIONAL_BOOL,nsubdomains:s.Z.OPTIONAL_STRING,unsubdomains:s.Z.OPTIONAL_BOOL,nemails:s.Z.OPTIONAL_STRING,unemails:s.Z.OPTIONAL_BOOL,nemailf:s.Z.OPTIONAL_STRING,unemailf:s.Z.OPTIONAL_BOOL,nemailml:s.Z.OPTIONAL_STRING,unemailml:s.Z.OPTIONAL_BOOL,nemailr:s.Z.OPTIONAL_STRING,unemailr:s.Z.OPTIONAL_BOOL,mysql:s.Z.OPTIONAL_STRING,umysql:s.Z.OPTIONAL_BOOL,domainptr:s.Z.OPTIONAL_STRING,udomainptr:s.Z.OPTIONAL_BOOL,ftp:s.Z.OPTIONAL_STRING,uftp:s.Z.OPTIONAL_BOOL,aftp:s.Z.OPTIONAL_STRING,cgi:s.Z.OPTIONAL_STRING,git:s.Z.OPTIONAL_STRING,php:s.Z.OPTIONAL_STRING,spam:s.Z.OPTIONAL_STRING,catchall:s.Z.OPTIONAL_STRING,ssl:s.Z.OPTIONAL_STRING,ssh:s.Z.OPTIONAL_STRING,userssh:s.Z.OPTIONAL_STRING,oversell:s.Z.OPTIONAL_STRING,cron:s.Z.OPTIONAL_STRING,sysinfo:s.Z.OPTIONAL_STRING,login_keys:s.Z.OPTIONAL_STRING,dnscontrol:s.Z.OPTIONAL_STRING}}),i=s.Z.post({url:"/CMD_MODIFY_RESELLER",params:{additional_bw:!0,action:"single",json:null},schema:{user:s.Z.REQUIRED_STRING,additional_bandwidth:s.Z.REQUIRED_STRING}})},"../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/pages/admin/users/resellers/view.vue?vue&type=style&index=0&id=23897272&prod&lang=scss&scoped=true&":function(){},"./js/api/commands/converters/customItems.ts":function(R,f,l){"use strict";l.d(f,{CR:function(){return v}});var s=l("../node_modules/ramda/es/index.js"),_=l("./js/api/commands/converters/index.ts"),c=l("./js/api/commands/utils/transduce.ts"),h=l("./js/api/commands/converters/toSelectData.ts");const v=p=>{const d={name:p.name,type:p.type==="listbox"?"select":p.type,label:p.string,description:p.desc||"",value:p.type==="checkbox"?(0,_.sw)(p.checked||"no"):p.value||""};return d.type==="select"?s.BPw(d,(0,h.M1)(p.select||{})):d},y=p=>(0,c.vr)([(0,c.uD)(d=>/^item\d+val$/.test(d)),(0,c.r5)(d=>{const i=d,t=d.replace("val","txt"),a=p[i],r=p[t];return{[a]:r}})],Object.keys(p)),x=(p,d)=>s.qCK(t=>{const a={name:t.name,type:t.type==="listbox"?"select":t.type,description:t.desc||"",value:t.value||"",label:t.string};return t.type==="listbox"?(a.value=t.default,a.options=y(t)):t.type==="checkbox"&&(a.value=t.checked==="yes"),a},s.BPw({name:p}),(0,c.vr)([(0,c.r5)(t=>{const[a,r]=s.Vl2("=",t);return{[a]:r}})]),s.Vl2("&"))(d);f.ZP={fromObject:v,fromString:x}},"./js/api/commands/converters/index.ts":function(R,f,l){"use strict";l.d(f,{l$:function(){return i.ZP},t0:function(){return s.t0},S8:function(){return s.S8},ql:function(){return s.ql},sw:function(){return s.sw},Qu:function(){return s.Qu},He:function(){return s.He},M1:function(){return d.M1},sf:function(){return a},cc:function(){return p}});var s=l("./js/api/commands/converters/primitive.ts"),_=l("../node_modules/monet/dist/monet.js"),c=l("./js/api/commands/types.ts");const h=r=>typeof r=="object"?_.Either.Right(r):_.Either.Left(new Error("Passed param is not an object")),v=r=>typeof r.usage=="string"?_.Either.Right(r):_.Either.Left(new Error("usage property is required")),y=r=>({usage:(0,s.He)(r.usage),limit:(0,s.Qu)(r.limit)}),x=({usage:r,limit:g})=>{let b=c.H.Normal;const $=Math.floor(r/g*100);return $>=100?b=c.H.OverUsed:$>80&&(b=c.H.AlmostUsed),{usage:r,limit:g,status:b}},p=r=>{const g=_.Either.Right(r).flatMap(h).flatMap(v).map(y).map(x);if(g.isLeft())throw g.left();return g.right()};var d=l("./js/api/commands/converters/toSelectData.ts"),i=l("./js/api/commands/converters/customItems.ts"),t=l("../node_modules/ramda/es/index.js");const a=r=>g=>{const{info:b}=g,$=t.CEd(["info"],g);return{columns:b.columns,rowsCount:Number(b.rows),rows:t.UID(r,t.VO0($))}}},"./js/api/commands/converters/toSelectData.ts":function(R,f,l){"use strict";l.d(f,{M1:function(){return x}});var s=l("../node_modules/monet/dist/monet.js"),_=l.n(s),c=l("./js/api/commands/utils/transduce.ts"),h=l("../node_modules/ramda/es/index.js");const v=p=>s.Maybe.Some(p).flatMap(d=>{const i=d.find(t=>t.selected==="yes");return i?s.Maybe.Some(i):s.Maybe.None()}).flatMap(d=>s.Maybe.fromNull(d.value)).orSome(""),y=(0,c.vr)([(0,c.r5)(p=>({[p.value]:p.text}))]),x=p=>{const d=(0,h.VO0)(p);return{value:v(d),options:y(d)}}},"./js/api/commands/types.ts":function(R,f,l){"use strict";l.d(f,{H:function(){return s}});var s;(function(_){_.Normal="normal",_.AlmostUsed="almost_used",_.OverUsed="overused"})(s||(s={}))},"./js/api/commands/utils/transduce.ts":function(R,f,l){"use strict";l.d(f,{Re:function(){return h},r5:function(){return _},uD:function(){return c},vr:function(){return d},zh:function(){return x}});var s=l("../node_modules/ramda/es/index.js");const _=i=>t=>(a,r)=>{const g=i(r);return t(a,g)},c=i=>t=>(a,r)=>i(r)?t(a,r):a,h=(i,t)=>(i.push(t),i),v=(i,t)=>s.BPw(i,t),y=(i,t,a,r)=>{const g=s.qCK(...a);return r.reduce(g(t),i)},x=s.WAo(y),p=x([],h),d=x({},v)},"./js/components/local/cgroups-editor.vue":function(R,f,l){"use strict";l.d(f,{Z:function(){return p}});var s=function(){var i=this,t=i._self._c;return i.enabled?t("app-page-section",{scopedSlots:i._u([{key:"section:title",fn:function(){return[t("div",{directives:[{name:"flex",rawName:"v-flex",value:{cross:"center"},expression:"{ cross: 'center' }"}]},[t("span",{domProps:{textContent:i._s(i.$gettext("Resource Limits"))}}),i._v(" "),i.$slots.tooltip||i.$scopedSlots.tooltip?t("ui-tooltip",{directives:[{name:"margin",rawName:"v-margin:left",value:.5,expression:"0.5",arg:"left"}]},[t("span",{domProps:{textContent:i._s(i.$gettext("Set maximum values reseller could set for his users."))}})]):i._e()],1)]},proxy:!0},{key:"default",fn:function(){return i._l(i.options,function(a){return t("ui-form-element",{key:a.name,scopedSlots:i._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:i._s(a.string)}})]},proxy:!0},{key:"tooltip",fn:function(){return[t("span",{domProps:{textContent:i._s(a.desc)}})]},proxy:!0},{key:"content",fn:function(){return[t("input-text",{attrs:{disabled:i.values[a.name].unlimited,placeholder:a.placeholder},on:{blur:function(r){return i.checkValue(a.name)}},scopedSlots:i._u([{key:"additions:right",fn:function(){return[t("input-checkbox-button",{attrs:{value:i.values[a.name].unlimited},on:{input:function(r){return i.setLimitState(a,r)}}},[t("span",{domProps:{textContent:i._s(i.$gettext("Unlimited"))}})])]},proxy:!0}],null,!0),model:{value:i.values[a.name].value,callback:function(r){i.$set(i.values[a.name],"value",r)},expression:"values[item.name].value"}})]},proxy:!0}],null,!0)})})},proxy:!0}],null,!1,4188802112)}):i._e()},_=[],c=l("../node_modules/ramda/es/index.js"),h={props:{options:{type:Array,required:!1,default:()=>[]}},data:()=>({values:{}}),computed:{enabled(){return this.options.length&&this.$_flags.server.cgroup},requestData(){return c.UID(d=>d.unlimited?"":d.value,this.values)}},watch:{requestData:{deep:!0,handler(d){this.$emit("update:cgroup-values",d)}}},created(){this.enabled&&this.options.forEach(d=>{const i=d.value||d.default,t=i==="";this.$set(this.values,d.name,{value:i,unlimited:t})})},methods:{setLimitState(d,i){this.values[d.name].unlimited=i,i===!1&&this.values[d.name].value===""&&(this.values[d.name].value=d.placeholder)},checkValue(d){this.values[d].value===""&&(this.values[d].unlimited=!0)}}},v=h,y=l("../node_modules/vue-loader/lib/runtime/componentNormalizer.js"),x=(0,y.Z)(v,s,_,!1,null,null,null),p=x.exports},"./js/pages/admin/users/resellers/view.vue":function(R,f,l){"use strict";l.r(f),l.d(f,{default:function(){return ne}});var s=function(){var e=this,n=e._self._c;return n("app-page",{attrs:{actions:[{label:e.$gettextInterpolate(e.$gettext("Login as %{user}"),{user:e.user}),handler:e.loginAsUser,icon:"list-users",theme:"safe"},{label:e.$gettext("Delete"),handler:e.$dialog("DELETE_RESELLER_DIALOG").open,icon:"#delete",theme:"danger"}]},scopedSlots:e._u([{key:"page:title",fn:function(){return[n("span",{domProps:{textContent:e._s(e.$gettextInterpolate(e.$gettext("View Reseller: %{ user }"),{user:e.user}))}})]},proxy:!0},{key:"default",fn:function(){return[n("app-page-section",[n("ui-tabs",{attrs:{tabs:[{id:"reseller",label:e.$gettext("Reseller")},{id:"user",label:e.$gettext("User")}],selected:e.usertype},on:{"update:selected":function(o){e.usertype=o}},scopedSlots:e._u([{key:"tab:reseller",fn:function(){return[n("app-page-section",[n("ui-tabs",{attrs:{tabs:[{id:"users",label:e.$gettext("Users")},{id:"usage",label:e.$gettext("Usage Statistics")},{id:"info",label:e.$gettext("Info")},{id:"comments",label:e.$gettext("Comments")},{id:"modify",label:e.$gettext("Modify")}],selected:e.tab},on:{"update:selected":function(o){e.tab=o}},scopedSlots:e._u([{key:"tab:users",fn:function(){return[n("users-table",e._b({},"users-table",{user:e.user},!1))]},proxy:!0},{key:"tab:usage",fn:function(){return[n("usage-table",{scopedSlots:e._u([{key:"bandwidth:limit:after",fn:function(){return[e.$api.info.additional_bandwidth!==!1?n("span",[e._v(`
                                            (
                                            `),n("span",{domProps:{textContent:e._s(e.$gettextInterpolate(e.$gettext("Additional Bandwidth: %{ amount }"),{amount:e.humanReadableSize(Number(e.$api.info.additional_bandwidth||0))}))}}),e._v(" "),n("ui-button-icon",{attrs:{icon:"pencil",size:"medium",title:e.$gettext("Temporary Bandwidth Increase")},on:{click:function(o){e.$dialog("ADDITIONAL_BANDWIDTH_DIALOG").open()}}}),e._v(`
                                            )
                                        `)],1):e._e()]},proxy:!0}])})]},proxy:!0},{key:"tab:info",fn:function(){return[n("info-table")]},proxy:!0},{key:"tab:comments",fn:function(){return[n("div",[n("textarea",{directives:[{name:"model",rawName:"v-model",value:e.comments,expression:"comments"}],domProps:{value:e.comments},on:{input:function(o){o.target.composing||(e.comments=o.target.value)}}}),e._v(" "),n("div",{directives:[{name:"flex",rawName:"v-flex",value:{main:"end"},expression:"{ main: 'end' }"},{name:"margin",rawName:"v-margin",value:[2,0],expression:"[2, 0]"}]},[n("ui-button",{attrs:{theme:"safe"},on:{click:e.saveComments}},[n("span",{domProps:{textContent:e._s(e.$gettext("Save Comments"))}})])],1)])]},proxy:!0},{key:"tab:modify",fn:function(){return[n("modify-reseller-tab",e._b({key:"modify-reseller"},"modify-reseller-tab",{user:e.user},!1))]},proxy:!0}])})],1)]},proxy:!0},{key:"tab:user",fn:function(){return[n("div")]},proxy:!0}])})],1),e._v(" "),n("ui-dialog",{attrs:{id:"DELETE_RESELLER_DIALOG",theme:"danger",title:e.$gettext("Delete Reseller")},scopedSlots:e._u([{key:"content",fn:function(){return[n("div",[n("span",{domProps:{textContent:e._s(e.$gettextInterpolate(e.$ngettext("Are you sure you want to delete %{user} and their %{n} user?","Are you sure you want to delete %{user} and their %{n} users?",e.$api.info.usage.nusers.usage),{user:e.user,n:e.$api.info.usage.nusers.usage}))}}),e._v(" "),e.$api.info.usage.nusers.usage?n("ui-tooltip",{attrs:{theme:"danger"}},[n("span",{domProps:{textContent:e._s(e.$gettext("You are deleting reseller that have users under control. If you proceed, these user accounts, along with ALL the associated website and email contents, which are not listed here, will also be removed."))}})]):e._e()],1)]},proxy:!0},{key:"buttons",fn:function(){return[n("ui-button",{attrs:{theme:"danger"},on:{click:e.deleteUser}},[n("span",{domProps:{textContent:e._s(e.$gettext("Delete"))}})])]},proxy:!0}])}),e._v(" "),e.info.skinInfo&&e.info.skinInfo.custom?n("reseller-skin-warning-dialog",e._b({on:{confirm:e.loginAsUserRequest}},"reseller-skin-warning-dialog",e.info.skinInfo,!1)):e._e(),e._v(" "),n("additional-bandwidth-dialog",e._b({},"additional-bandwidth-dialog",{user:e.user},!1)),e._v(" "),n("change-password-dialog",{ref:"cpd"})]},proxy:!0},{key:"bottom:links",fn:function(){return[n("ui-link",{attrs:{bullet:""},on:{click:e.changePassword}},[n("span",{domProps:{textContent:e._s(e.$gettext("Change Password"))}})])]},proxy:!0}])})},_=[],c=l("./js/api/commands/admin/users/resellers.js"),h=l("./js/api/commands/admin/users/actions.js"),v=l("./js/composables/filters.ts"),y=l("./js/vue-globals/mixins.js"),x=l("./js/components/local/reseller-skin-warning-dialog.vue"),p=function(){var e=this,n=e._self._c;return n("ui-api-table",e._b({attrs:{"vertical-layout":e.clientStore.isPhone,"disable-select":""},scopedSlots:e._u([{key:"col:username",fn:function({username:o,item:m}){return[n("ui-grid",[n("ui-link",{attrs:{name:"reseller/users/view",params:{user:o}}},[e._v(`
                `+e._s(o)+`
            `)]),e._v(" "),m.suspended?n("ui-tooltip",{attrs:{theme:"danger",icon:"warning"}},[n("span",{domProps:{textContent:e._s(e.$gettext("Suspended"))}})]):e._e()],1)]}},{key:"col:bandwidth",fn:function({bandwidth:o}){return[n("ui-limited-usage",e._b({},"ui-limited-usage",o,!1))]}},{key:"col:quota",fn:function({quota:o}){return[n("ui-limited-usage",e._b({},"ui-limited-usage",o,!1))]}},{key:"col:vdomains",fn:function({vdomains:o}){return[n("ui-limited-usage",e._b({attrs:{plain:""}},"ui-limited-usage",o,!1))]}}])},"ui-api-table",{command:e.$commands.getStats,property:"users",columns:{username:{label:e.$gettext("Username"),grow:!0},bandwidth:{label:e.$gettext("Bandwidth"),getClass:o=>o.bandwidth.status?`--usage:${o.bandwidth.status}`:""},quota:{label:e.$gettext("Disk Usage"),getClass:o=>o.bandwidth.status?`--usage:${o.quota.status}`:""},vdomains:e.$gettext("# of Domains"),remove:""},requestData:{user:e.user}},!1))},d=[],i=l("./js/stores/index.ts"),t={commands:{getStats:c.fy},props:{user:{type:String,required:!0}},computed:{...(0,i.Kc)(["client"])}},a=t,r=l("../node_modules/vue-loader/lib/runtime/componentNormalizer.js"),g=(0,r.Z)(a,p,d,!1,null,null,null),b=g.exports,$=function(){var e=this,n=e._self._c;return n("ui-table",{attrs:{items:e.usageData,vertical:e.clientStore.isPhone}},[n("ui-column",{attrs:{id:"label",label:e.$gettext("Setting")}}),e._v(" "),n("ui-column",{attrs:{id:"usage",label:e.$gettext("Usage")},scopedSlots:e._u([{key:"default",fn:function(o){return[e._t(`${o.id}:usage:before`),e._v(" "),e._t(`${o.id}:usage`,function(){return[n("span",{domProps:{textContent:e._s(e.formatUsageText(o))}})]}),e._v(" "),e._t(`${o.id}:usage:after`)]}}],null,!0)}),e._v(" "),n("ui-column",{attrs:{id:"allocated",label:e.$gettext("Allocated")},scopedSlots:e._u([{key:"default",fn:function(o){return[e._t(`${o.id}:allocated:before`),e._v(" "),e._t(`${o.id}:allocated`,function(){return[n("span",{domProps:{textContent:e._s(e.formatAllocatedText(o))}})]}),e._v(" "),e._t(`${o.id}:allocated:after`)]}}],null,!0)}),e._v(" "),n("ui-column",{attrs:{id:"limit",label:e.$gettext("Limit")},scopedSlots:e._u([{key:"default",fn:function(o){return[e._t(`${o.id}:limit:before`),e._v(" "),e._t(`${o.id}:limit`,function(){return[n("span",{domProps:{textContent:e._s(e.formatLimitText(o))}})]}),e._v(" "),e._t(`${o.id}:limit:after`)]}}],null,!0)})],1)},I=[],P={api:[{command:c.fy,bind:{"response.usage":"usage","response.deleted_user_bandwidth":"deletedUserBandwidth"}}],computed:{usage(){return{...this.$api.usage,deleted_user_bandwidth:this.$api.deletedUserBandwidth}},usageData(){const u={bandwidth:this.$gettext("Bandwidth"),deleted_user_bandwidth:this.$gettext("Deleted User Bandwidth"),quota:this.$gettext("Disk Usage"),inode:this.$gettext("Inode"),vdomains:this.$gettext("# of Domains"),nsubdomains:this.$gettext("# of Subdomains"),nemails:this.$gettext("E-mail Accounts"),nemailf:this.$gettext("E-mail Forwarders"),nemailml:this.$gettext("Mailing Lists"),nemailr:this.$gettext("Autoresponders"),mysql:this.$gettext("# of DBs"),domainptr:this.$gettext("Domain Pointers"),ftp:this.$gettext("FTP Accounts"),nusers:this.$gettext("User Accounts")};return Object.entries(u).filter(([e])=>this.usage[e]).map(([e,n])=>({id:e,...this.usage[e],label:n,bytes:["bandwidth","quota","deleted_user_bandwidth"].includes(e)}))},...(0,i.Kc)(["client"])},methods:{formatUsageText(u){return u.bytes?(0,v.eB)(u.usage):u.usage},formatAllocatedText(u){return u.allocated===1/0?this.$gettext("Unlimited"):u.bytes&&u.allocated?(0,v.eB)(u.allocated):u.allocated},formatLimitText(u){return u.limit===1/0?this.$gettext("Unlimited"):u.bytes&&u.limit?(0,v.eB)(u.limit):u.limit}}},T=P,N=(0,r.Z)(T,$,I,!1,null,null,null),w=N.exports,D=function(){var e=this,n=e._self._c;return n("div",[e._l(e.shownInfoLabels,function(o,m){return n("ui-form-element",{key:m,scopedSlots:e._u([{key:"title",fn:function(){return[n("span",{domProps:{textContent:e._s(o)}})]},proxy:!0},{key:"content",fn:function(){return[n("input-text",{attrs:{disabled:"",value:e.info[m]}})]},proxy:!0}],null,!0)})}),e._v(" "),e._l(e.statsLabels,function(o,m){return n("ui-form-element",{key:m,attrs:{"vertical-on-phone":!1,"grow-title":e.clientStore.isPhone,underline:!e.clientStore.isPhone},scopedSlots:e._u([{key:"title",fn:function(){return[n("span",{domProps:{textContent:e._s(o)}})]},proxy:!0},{key:"content",fn:function(){return[n("div",[n("ui-badge",{attrs:{theme:e.stats[m]?"safe":"danger",label:e.stats[m]?e.$gettext("Enabled"):e.$gettext("Disabled")}})],1)]},proxy:!0}],null,!0)})}),e._v(" "),e.cgroup.length?n("app-page-section",{scopedSlots:e._u([{key:"section:title",fn:function(){return[n("span",{domProps:{textContent:e._s(e.$gettext("Resource Limits"))}})]},proxy:!0}],null,!1,1996196552)},[e._v(" "),n("ui-table",{attrs:{items:[e.cgroup],transposed:""}},e._l(e.cgroup,function(o){return n("ui-column",{key:o.name,attrs:{id:o.name,label:o.string}},[e._v(`
                `+e._s(o.value)+`
            `)])}),1)],1):e._e()],2)},k=[],E=l("../node_modules/ramda/es/index.js"),A={api:[{command:c.fy,bind:"stats"},{command:c.Rh,bind:"modify"}],computed:{stats(){return this.$api.stats.stats},info(){return this.$api.stats.info},cgroup(){return this.$api.modify.cgroup.filter(u=>u.value)},shownInfoLabels(){return E.zGw(E.Zpf,E.hXT(([u])=>this.info[u]),E.Pen)(this.infoLabels)},...(0,i.Kc)(["client"])},created(){this.statsLabels={ssh:this.$gettext("SSH"),userssh:this.$gettext("User SSH"),ssl:this.$gettext("SSL"),cgi:this.$gettext("CGI"),git:this.$gettext("Git"),wordpress:this.$gettext("Wordpress"),clamav:this.$gettext("ClamAV"),nginx_unit:this.$gettext("Nginx Unit"),php:this.$gettext("PHP"),spam:this.$gettext("SpamAssassin"),catchall:this.$gettext("Catch-All E-mail"),aftp:this.$gettext("Anonymous FTP"),cron:this.$gettext("Cron Jobs"),redis:this.$gettext("Redis"),sysinfo:this.$gettext("System Info"),login_keys:this.$gettext("Login Keys"),dnscontrol:this.$gettext("DNS Control"),oversell:this.$gettext("Oversell"),serverip:this.$gettext("Can use Server IP")};const u=this.$_ctx.session.features.server;u.redis===!1&&delete this.statsLabels.redis,u.git===!1&&delete this.statsLabels.git,this.infoLabels={ips:this.$gettext("# of IPs"),ns1:this.$gettext("Name Server 1"),ns2:this.$gettext("Name Server 2"),package:this.$gettext("Package"),original_package:this.$gettext("Original Package")}}},j=A,U=(0,r.Z)(j,D,k,!1,null,null,null),C=U.exports,Z=function(){var e=this,n=e._self._c;return n("ui-dialog",{attrs:{id:"ADDITIONAL_BANDWIDTH_DIALOG",title:e.$gettext("Temporary Bandwidth Increase")},on:{"dialog:open":e.setInitialValue},scopedSlots:e._u([{key:"content",fn:function(){return[n("ui-form-element",{attrs:{vertical:"","path-segment":"changelog/version-1.37.0.html#temporary-additional-bandwidth",group:"additionalBandwith",validators:{required:!0}},scopedSlots:e._u([{key:"title",fn:function(){},proxy:!0},{key:"content",fn:function(){return[n("input-size",{attrs:{powers:{MB:20,GB:30,TB:40}},model:{value:e.amount,callback:function(o){e.amount=o},expression:"amount"}})]},proxy:!0}])})]},proxy:!0},{key:"buttons",fn:function(){return[n("ui-button",{attrs:{"validate-group":"additionalBandwidth",theme:"primary"},on:{click:e.increaseBandwidth}},[n("span",{domProps:{textContent:e._s(e.$gettext("Increase Bandwidth"))}})])]},proxy:!0}])})},M=[];const B=1048576;var G={api:[{command:c.fy,bind:{"response.additional_bandwidth":"additional_bandwidth"}}],props:{user:{type:String,required:!0}},data:()=>({amount:0}),methods:{setInitialValue(){this.amount=this.$api.additional_bandwidth||0},async increaseBandwidth(){await(0,c.YY)({user:this.user,additional_bandwidth:String(this.amount/B)}),Object.assign(this.$data,this.$options.data.apply(this)),(0,c.fy)({user:this.user})}}},Q=G,W=(0,r.Z)(Q,Z,M,!1,null,null,null),F=W.exports,V=l("./js/components/local/change-user-password-dialog.vue"),K=function(){var e=this,n=e._self._c;return e.loading?n("ui-center",{attrs:{height:"20rem"}},[n("ui-loader-icon",{attrs:{size:32}})],1):n("div",[n("app-page-section",[n("ui-form-element",{scopedSlots:e._u([{key:"title",fn:function(){return[n("span",{domProps:{textContent:e._s(e.$gettext("Set Package to"))}})]},proxy:!0},{key:"content",fn:function(){return[n("input-select",{attrs:{options:e.data.packages},scopedSlots:e._u([{key:"additions:right",fn:function(){return[n("ui-button",{attrs:{theme:"safe",size:"normal",disabled:!e.packageName},on:{click:e.savePackage}},[n("span",{domProps:{textContent:e._s(e.$gettext("Save"))}})])]},proxy:!0}]),model:{value:e.packageName,callback:function(o){e.packageName=o},expression:"packageName"}})]},proxy:!0}])})],1),e._v(" "),n("app-page-section",{scopedSlots:e._u([{key:"section:title",fn:function(){return[n("span",{domProps:{textContent:e._s(e.$gettext("Manually Change Settings"))}})]},proxy:!0},{key:"default",fn:function(){return[e._l(e.shownLimits,function(o,m){return n("ui-form-element",{key:m,attrs:{group:"modifyReseller",validators:{required:!e.limits[m].unlimited}},scopedSlots:e._u([{key:"title",fn:function(){return[n("span",{domProps:{textContent:e._s(e.$gettext(o))}})]},proxy:!0},{key:"content",fn:function(){return[n("ui-input-group",{scopedSlots:e._u([{key:"input",fn:function(){return[n(["bandwidth","quota"].includes(m)?"input-size":"input-text",{ref:"limits",refInFor:!0,tag:"component",attrs:{number:"",disabled:e.limits[m].unlimited,"data-key":m},model:{value:e.limits[m].value,callback:function(O){e.$set(e.limits[m],"value",O)},expression:"limits[key].value"}})]},proxy:!0},{key:"additions:right",fn:function(){return[n("ui-button",{on:{click:function(O){return e.toggleLimit(m)}}},[n("input-checkbox",{attrs:{model:e.limits[m].unlimited,label:e.$gettext("Unlimited")}})],1)]},proxy:!0}],null,!0)})]},proxy:!0}],null,!0)})}),e._v(" "),e._l(e.shownFeatures,function(o,m){return n("ui-form-element",{key:m,class:{dimmed:!e.features[m]},attrs:{"vertical-on-phone":!1,reverse:e.clientStore.isPhone},scopedSlots:e._u([{key:"title",fn:function(){return[n("span",{domProps:{textContent:e._s(e.$gettext(o))}})]},proxy:!0},{key:"content",fn:function(){return[n("input-checkbox",{model:{value:e.features[m],callback:function(O){e.$set(e.features,m,O)},expression:"features[key]"}})]},proxy:!0}],null,!0)})}),e._v(" "),e._l(e.customItems,function(o){return n("ui-form-element",{key:o.name,attrs:{"vertical-on-phone":o.type!=="checkbox",reverse:o.type==="checkbox"&&e.clientStore.isPhone},scopedSlots:e._u([{key:"title",fn:function(){return[n("span",{domProps:{textContent:e._s(o.label)}})]},proxy:!0},o.description?{key:"tooltip",fn:function(){return[n("span",{domProps:{textContent:e._s(o.description)}})]},proxy:!0}:null,{key:"content",fn:function(){return[o.type==="text"?n("input-text",{model:{value:o.value,callback:function(m){e.$set(o,"value",m)},expression:"customItem.value"}}):o.type==="checkbox"?n("input-checkbox",{model:{value:o.value,callback:function(m){e.$set(o,"value",m)},expression:"customItem.value"}}):o.type==="listbox"?n("input-select",{attrs:{options:o.options},model:{value:o.value,callback:function(m){e.$set(o,"value",m)},expression:"customItem.value"}}):e._e()]},proxy:!0}],null,!0)})}),e._v(" "),n("cgroups-editor",{attrs:{options:e.$api.data.cgroup},on:{"update:cgroup-values":function(o){e.cgroupValues=o}}})]},proxy:!0},{key:"footer:buttons",fn:function(){return[n("ui-button",{attrs:{"validate-group":"modifyReseller",theme:"safe"},on:{click:e.savePackageData}},[n("span",{domProps:{textContent:e._s(e.$gettext("Save"))}})])]},proxy:!0}])})],1)},H=[],z=l("./js/components/local/cgroups-editor.vue"),S=l("./js/modules/utils/index.js"),Y={components:{CgroupsEditor:z.Z},props:{user:{type:String,required:!0,default:""}},data:()=>({loading:!0,packageName:"",limits:{},features:{},customItems:[],cgroupValues:{}}),api:[{command:c.Rh,bind:"data"}],computed:{data(){return this.$api.data},packageData(){const u=S.fp.transformObject(({value:m,unlimited:O},L)=>({[L]:["bandwidth","quota"].includes(L)?`${m} B`:m,[`u${L}`]:O||null})),e=S.fp.mapValues(m=>m?"ON":null),n=S.fp.transformObject(({value:m,name:O})=>({[O]:m===!0?"ON":m}));return{...S.fp.filter(S.fp.notEmpty)({...u(this.limits),...n(this.customItems),...e(this.features)}),...this.cgroupValues}},shownLimits(){return E.D95((u,e)=>e==="inode"?this.data.haveInode:typeof this.limits[e]!="undefined",this.limitLabels)},shownFeatures(){return E.D95((u,e)=>u&&typeof this.features[e]!="undefined",this.featureLabels)},...(0,i.Kc)(["client"])},created(){this.limitLabels={bandwidth:this.$gettext("Bandwidth (MB)"),quota:this.$gettext("Disk Space (MB)"),inode:this.$gettext("Inode"),vdomains:this.$gettext("Domains"),nsubdomains:this.$gettext("Sub-Domains"),nemails:this.$gettext("E-mail Accounts"),nemailf:this.$gettext("E-mail Forwarders"),nemailml:this.$gettext("Mailing Lists"),nemailr:this.$gettext("Autoresponders"),mysql:this.$gettext("MySQL Databases"),domainptr:this.$gettext("Domain Pointers"),ftp:this.$gettext("FTP Accounts"),nusers:this.$gettext("User Accounts")},this.featureLabels={aftp:this.$gettext("Anonymous FTP Accounts"),cgi:this.$gettext("CGI Access"),git:this.$gettext("Git"),wordpress:this.$gettext("Wordpress"),clamav:this.$gettext("ClamAV"),nginx_unit:this.$gettext("Nginx Unit"),php:this.$gettext("PHP Access"),spam:this.$gettext("SpamAssassin"),catchall:this.$gettext("Catch-All E-mail"),ssl:this.$gettext("SSL Access"),ssh:this.$gettext("SSH Access"),userssh:this.$gettext("SSH Access for Users"),oversell:this.$gettext("Allow Overselling"),cron:this.$gettext("Cron Jobs"),redis:this.$gettext("Redis"),sysinfo:this.$gettext("System Info"),login_keys:this.$gettext("Login Keys"),dnscontrol:this.$gettext("DNS Control")};const u=this.$_ctx.session.features.server;u.redis===!1&&delete this.featureLabels.redis,u.wordpress===!1&&delete this.featureLabels.wordpress,u.git===!1&&delete this.featureLabels.git,u.clamav===!1&&delete this.featureLabels.clamav,u.unit===!1&&delete this.featureLabels.nginx_unit},async mounted(){const u=await this.loadUserData();this.packageName=u.package,this.limits=S._.cloneDeep(u.packageData.limits),this.features=S._.cloneDeep(u.packageData.features),this.customItems=S._.cloneDeep(u.custom)},methods:{async loadUserData(){this.loading=!0;const u=await(0,c.Rh)({user:this.user});return this.$nextTick(()=>{this.loading=!1}),u},async savePackage(){await(0,c.pw)({user:this.user,package:this.packageName}),this.$_useStore("user").name===this.user&&this.$_ctx.session.loadUserConfig(),this.loadUserData()},async savePackageData(){await(0,c.Zg)({user:this.user,...this.packageData}),this.$_useStore("user").name===this.user&&this.$_ctx.session.loadUserConfig()},toggleLimit(u){this.limits[u].unlimited=!this.limits[u].unlimited;const e=this.$refs.limits.find(n=>n.$attrs["data-key"]===u);this.$nextTick(()=>e.$validate(e.value))}}},q=Y,J=(0,r.Z)(q,K,H,!1,null,null,null),X=J.exports,ee={name:"ResellerView",preload:[c.fy,c.Rf,c.Rh],api:[{command:c.fy,bind:"info"}],components:{ResellerSkinWarningDialog:x.Z,AdditionalBandwidthDialog:F,UsersTable:b,UsageTable:w,InfoTable:C,ChangePasswordDialog:V.Z,ModifyResellerTab:X},mixins:[(0,y.$bindTab)({param:"tab",defaultTab:"users"})],props:{user:{type:String,default:""}},data(){return{comments:""}},computed:{info(){return this.$api.info},usertype:{get(){return"reseller"},set(u){u==="user"&&this.$router.replace({name:"reseller/users/view",params:{user:this.user}})}}},created(){this.comments=this.info.comments},methods:{humanReadableSize:v.eB,loginAsUser(){this.info.skinInfo&&this.info.skinInfo.custom?this.$dialog("RESELLER_SKIN_WARNING_DIALOG").open():this.loginAsUserRequest()},loginAsUserRequest(){this.$_ctx.session.impersonateUser(this.user)},saveComments(){(0,h.vk)({user:this.user,comments:this.comments})},async deleteUser(){await(0,h.Vt)({select:[this.user],location:"CMD_SHOW_RESELLER"})&&this.$router.replace("/admin/users/resellers")},changePassword(){this.$refs.cpd.show(this.user)}}},te=ee,ae=l("../node_modules/vue-style-loader/index.js!../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/pages/admin/users/resellers/view.vue?vue&type=style&index=0&id=23897272&prod&lang=scss&scoped=true&"),se=(0,r.Z)(te,s,_,!1,null,"23897272",null),ne=se.exports},"../node_modules/vue-style-loader/index.js!../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/pages/admin/users/resellers/view.vue?vue&type=style&index=0&id=23897272&prod&lang=scss&scoped=true&":function(R,f,l){var s=l("../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/pages/admin/users/resellers/view.vue?vue&type=style&index=0&id=23897272&prod&lang=scss&scoped=true&");s.__esModule&&(s=s.default),typeof s=="string"&&(s=[[R.id,s,""]]),s.locals&&(R.exports=s.locals);var _=l("../node_modules/vue-style-loader/lib/addStylesClient.js").Z,c=_("af5c5b68",s,!0,{})}}]);