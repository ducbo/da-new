(self.webpackChunk=self.webpackChunk||[]).push([[2928],{"../node_modules/date-fns/esm/formatDistance/index.js":function(U,E,o){"use strict";o.d(E,{Z:function(){return N}});var a=o("../node_modules/date-fns/esm/_lib/defaultOptions/index.js"),l=o("../node_modules/date-fns/esm/toDate/index.js"),p=o("../node_modules/date-fns/esm/_lib/requiredArgs/index.js");function n(u,c){(0,p.Z)(2,arguments);var d=(0,l.Z)(u),j=(0,l.Z)(c),$=d.getTime()-j.getTime();return $<0?-1:$>0?1:$}function m(u,c){(0,p.Z)(2,arguments);var d=(0,l.Z)(u),j=(0,l.Z)(c),$=d.getFullYear()-j.getFullYear(),C=d.getMonth()-j.getMonth();return $*12+C}function v(u){(0,p.Z)(1,arguments);var c=(0,l.Z)(u);return c.setHours(23,59,59,999),c}function D(u){(0,p.Z)(1,arguments);var c=(0,l.Z)(u),d=c.getMonth();return c.setFullYear(c.getFullYear(),d+1,0),c.setHours(23,59,59,999),c}function S(u){(0,p.Z)(1,arguments);var c=(0,l.Z)(u);return v(c).getTime()===D(c).getTime()}function b(u,c){(0,p.Z)(2,arguments);var d=(0,l.Z)(u),j=(0,l.Z)(c),$=n(d,j),C=Math.abs(m(d,j)),f;if(C<1)f=0;else{d.getMonth()===1&&d.getDate()>27&&d.setDate(30),d.setMonth(d.getMonth()-$*C);var A=n(d,j)===-$;S((0,l.Z)(u))&&C===1&&n(u,j)===1&&(A=!1),f=$*(C-Number(A))}return f===0?0:f}function R(u,c){return(0,p.Z)(2,arguments),(0,l.Z)(u).getTime()-(0,l.Z)(c).getTime()}var w={ceil:Math.ceil,round:Math.round,floor:Math.floor,trunc:function(c){return c<0?Math.ceil(c):Math.floor(c)}},I="trunc";function M(u){return u?w[u]:w[I]}function i(u,c,d){(0,p.Z)(2,arguments);var j=R(u,c)/1e3;return M(d==null?void 0:d.roundingMethod)(j)}var h=o("../node_modules/date-fns/esm/_lib/defaultLocale/index.js");function r(u,c){if(u==null)throw new TypeError("assign requires that input parameter not be null or undefined");for(var d in c)Object.prototype.hasOwnProperty.call(c,d)&&(u[d]=c[d]);return u}function e(u){return r({},u)}var t=o("../node_modules/date-fns/esm/_lib/getTimezoneOffsetInMilliseconds/index.js"),s=1440,g=2520,_=43200,P=86400;function N(u,c,d){var j,$;(0,p.Z)(2,arguments);var C=(0,a.j)(),f=(j=($=d==null?void 0:d.locale)!==null&&$!==void 0?$:C.locale)!==null&&j!==void 0?j:h.Z;if(!f.formatDistance)throw new RangeError("locale must contain formatDistance property");var A=n(u,c);if(isNaN(A))throw new RangeError("Invalid time value");var x=r(e(d),{addSuffix:Boolean(d==null?void 0:d.addSuffix),comparison:A}),O,Z;A>0?(O=(0,l.Z)(c),Z=(0,l.Z)(u)):(O=(0,l.Z)(u),Z=(0,l.Z)(c));var L=i(Z,O),W=((0,t.Z)(Z)-(0,t.Z)(O))/1e3,y=Math.round((L-W)/60),T;if(y<2)return d!=null&&d.includeSeconds?L<5?f.formatDistance("lessThanXSeconds",5,x):L<10?f.formatDistance("lessThanXSeconds",10,x):L<20?f.formatDistance("lessThanXSeconds",20,x):L<40?f.formatDistance("halfAMinute",0,x):L<60?f.formatDistance("lessThanXMinutes",1,x):f.formatDistance("xMinutes",1,x):y===0?f.formatDistance("lessThanXMinutes",1,x):f.formatDistance("xMinutes",y,x);if(y<45)return f.formatDistance("xMinutes",y,x);if(y<90)return f.formatDistance("aboutXHours",1,x);if(y<s){var G=Math.round(y/60);return f.formatDistance("aboutXHours",G,x)}else{if(y<g)return f.formatDistance("xDays",1,x);if(y<_){var z=Math.round(y/s);return f.formatDistance("xDays",z,x)}else if(y<P)return T=Math.round(y/_),f.formatDistance("aboutXMonths",T,x)}if(T=b(Z,O),T<12){var X=Math.round(y/_);return f.formatDistance("xMonths",X,x)}else{var B=T%12,k=Math.floor(T/12);return B<3?f.formatDistance("aboutXYears",k,x):B<9?f.formatDistance("overXYears",k,x):f.formatDistance("almostXYears",k+1,x)}}},"./js/api/commands/admin/users/actions.js":function(U,E,o){"use strict";o.d(E,{Ss:function(){return n},Vt:function(){return m},XB:function(){return S},f1:function(){return p},uV:function(){return v},vk:function(){return D}});var a=o("./js/api/command/index.js");const l=a.Z.post({url:"/CMD_SELECT_USERS",notifySuccess:!0,notifyError:!0,params:{location:"CMD_ALL_USER_SHOW"},schema:{select:a.Z.ROWS},blocking:!0}),p=l.extend({params:{dosuspend:!0},schema:{reason:a.Z.REQUIRED_STRING},blocking:!0}),n=l.extend({params:{dounsuspend:!0},blocking:!0}),m=l.extend({params:{delete:!0,confirmed:!0},schema:{leave_dns:a.Z.OPTIONAL_BOOL},blocking:!0}),v=a.Z.post({url:"/CMD_ACCOUNT_ADMIN",params:{action:"create"},schema:{username:a.Z.REQUIRED_STRING,email:a.Z.REQUIRED_STRING,passwd:a.Z.REQUIRED_STRING,passwd2:a.Z.REQUIRED_STRING,notify:a.Z.REQUIRED_BOOL}}),D=a.Z.post({url:"/CMD_COMMENTS",params:{location:"CMD_SHOW_RESELLER"},schema:{user:a.Z.REQUIRED_STRING,comments:a.Z.REQUIRED_STRING}}),S=a.Z.post({url:"/CMD_MOVE_USERS",id:"USERS_COUNT_PER_RESELLER",response:{},after:b=>b.flow(b.getProp("data_list"),b.mapValues(R=>R.length))})},"./js/api/commands/admin/users/index.js":function(U,E,o){"use strict";o.d(E,{R:function(){return l},v:function(){return p}});var a=o("./js/api/command/index.js");const l=a.Z.get({id:"ALL_USERS",url:"/CMD_ALL_USER_SHOW",pagination:!0,params:{bytes:!0},after:n=>n.flow(n.wrap("users"),n.moveProp({"users.reasons":"options.reasons","users.add_leave_dns":"options.add_leave_dns","users.remote_server":"options.remote_servers","users.RESULT":"options.connectionError"}),n.mapProp("users",n.toTable(n.flow(n.mapArrayProps({username:n.getProp("value"),is_user:n.feedWith(1,n.flow(n.getProp("username.is_user"),n.convert.toAppBoolean)),suspended:n.flow(n.getProp("value"),n.convert.toAppBoolean),reason:n.feedWith(1,m=>m.suspended.reason||"none"),vdomains:n.toLimitedUsage(),bandwidth:n.toLimitedUsage(),quota:n.toLimitedUsage(),date_created:n.convert.toAppDate,mysql:m=>{if(!m)return;const[v,D]=m.split("/").map(S=>S.trim());return n.toLimitedUsage()({limit:Number(D)||1/0,usage:v})}}),n.mapArray(m=>({...m,test:"test"}))))),n.mapProp("options",n.mapProps({add_leave_dns:n.convert.toAppBoolean,connectionError:m=>(m||"").split("<br>\\n").filter(n.notEmpty).join("<br>"),remote_servers:n.flow(m=>m||{},n.mapValues(({ssl:m,port:v},D)=>`${n.convert.toAppBoolean(m)?"https":"http"}://${D}:${v}`)),reasons:n.toSelect})))}),p=a.Z.get({id:"ADMINS",url:"/CMD_ADMIN_SHOW",params:{bytes:!0},pagination:!0,after:n=>n.flow(n.wrap("admins"),n.moveProp({"admins.reasons":"reasons"}),n.mapProp("admins",n.toTable(n.mapArrayProps({nusers:n.convert.toAppNumber,suspended:n.flow(n.getProp("value"),n.isEqual("no:"),n.not),reason:n.feedWith(1,m=>m.suspended.reason||"none"),vdomains:n.toLimitedUsage(),bandwidth:n.toLimitedUsage(),quota:n.toLimitedUsage()}))),n.mapProp("reasons",n.toSelect))})},"../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/components/local/user-domains.vue?vue&type=style&index=0&id=67dd5324&prod&lang=scss&":function(){},"./js/composables/dateFilter.ts":function(U,E,o){"use strict";o.d(E,{W:function(){return m},f:function(){return p.f}});var a=o("../node_modules/ramda/es/index.js"),l=o("../node_modules/date-fns/esm/format/index.js"),p=o("./js/modules/date-formats.ts"),n=o("./js/modules/customizations/date-formats/default.ts");const m=a.WAo((v,D)=>{if(D)try{return(0,l.Z)(D,p.f.value[v])}catch(S){return console.warn(`Given ${v} format is incorrect:
${S.message}`),(0,l.Z)(D,n.d[v])}return""})},"./js/composables/filters.ts":function(U,E,o){"use strict";o.d(E,{Q0:function(){return i},aS:function(){return r},d5:function(){return h},eB:function(){return w},hT:function(){return b},kC:function(){return S},n9:function(){return M},zM:function(){return R}});var a=o("../node_modules/date-fns/esm/formatDistance/index.js"),l=o("../node_modules/punycode/punycode.es6.js"),p=o("./js/composables/dateFilter.ts"),n=o("./js/composables/gettext.ts");const{$gettext:m,$ngettext:v,$gettextInterpolate:D}=(0,n.Z)(),S=t=>{var s;return t?((s=t.at(0))===null||s===void 0?void 0:s.toUpperCase())+t.slice(1):""},b=(t,s="datetime")=>(0,p.W)(s,t),R=t=>(0,a.Z)(t,new Date),w=(t,s=1024)=>{const g=Number(t);if(!g)return"0 B";const _=["B","KB","MB","GB","TB","PB","EB","ZB","YB"],P=Math.floor(Math.log(g)/Math.log(s));return`${parseFloat((g/s**P).toFixed(2))} ${_[P]}`},I=t=>{try{return(0,l.xX)(t)}catch(s){return t}},M=t=>(0,l.xX)(t),i=t=>{if(!t||!t.includes("@"))return t;const[s,g]=t.split("@");return[s,I(g)].join("@")},h=t=>{if(t<60)return m("less than a minute");const s=Math.floor(t/60)%60,g=Math.floor(t/3600)%24,_=Math.floor(t/(3600*24)),P=[_?v("%{days} day","%{days} days",_):null,g?v("%{hours} hour","%{hours} hours",g):null,s?v("%{minutes} minute","%{minutes} minutes",s):null].filter(Boolean).join(", ");return D(P,{days:_,hours:g,minutes:s})},r=(t,s)=>t.length<=s?t:`${t.substring(0,s)}...`,e=()=>({capitalize:S,date:b,distanceFromNow:R,humanReadableSize:w,p6eUnicode:M,p6eUnicodeEmail:i,formatUptime:h,truncateString:r})},"./js/components/local/user-domains.vue":function(U,E,o){"use strict";o.d(E,{Z:function(){return I}});var a=function(){var i=this,h=i._self._c;return h("div",{class:{"scrollbar:primary":!i.clientStore.isPhone},style:{"overflow-x":"auto","min-width":i.clientStore.isPhone?"auto":"15rem"}},[i._l(i.shownDomains,function(r,e){return h("div",{directives:[{name:"flex",rawName:"v-flex",value:{cross:"center"},expression:"{ cross: 'center' }"}],key:e},[h("a",{attrs:{href:`http://${e}`,target:"_blank"}},[i._v(`
            `+i._s(i.p6eUnicode(e))+`
        `)]),i._v(`
        \xA0
        `),r.length&&i.showPointers!==0?h("ui-tooltip",{scopedSlots:i._u([{key:"trigger",fn:function(){return[h("span",{staticClass:"txt:bold",domProps:{textContent:i._s(i.$gettext("(pointers)"))}})]},proxy:!0}],null,!0)},[i._v(" "),h(i.showPointers===1?"ul":"ol",{tag:"component",staticClass:"wrap:nowrap user-domains--pointers"},i._l(r,function(t){return h("li",{key:t},[h("a",{attrs:{href:`http://${t}`,target:"_blank"}},[i._v(`
                        `+i._s(i.p6eUnicode(t))+`
                    `)])])}),0)],1):i._e()],1)}),i._v(" "),i.showExpandButton&&!i.showAllDomains?h("ui-button",{attrs:{theme:"light",size:"small"},on:{click:function(r){i.showAll=!0}}},[h("span",{domProps:{textContent:i._s(i.$gettext("show all..."))}}),i._v(" "),h("ui-icon",{directives:[{name:"margin",rawName:"v-margin",value:[,,,1],expression:"[, , , 1]"}],attrs:{id:"caret-down",size:"small"}})],1):i._e()],2)},l=[],p=o("./js/stores/index.ts"),n=o("./js/vue-globals/helpers.js"),m=o("../node_modules/ramda/es/index.js"),v=o("./js/composables/filters.ts"),D={props:{domains:{type:Object,required:!0,default:()=>({})}},data:()=>({showAll:!1}),computed:{showDomainLimit:(0,n.YM)("tables/userDomainsLimit"),showPointers(){const M=this.$_session.showPointersInList;return typeof M=="undefined"?1:M},shownDomainNumber(){return Number(this.showDomainLimit)},showExpandButton(){return Object.keys(this.domains).length>this.shownDomainNumber},showAllDomains(){return this.showAll||Object.keys(this.domains).length===this.shownDomainNumber+1},shownDomains(){if(this.showAllDomains)return this.domains;const M=m.tPi(0,this.shownDomainNumber,m.XPQ(this.domains));return m.eiS(M,this.domains)},...(0,p.Kc)(["client"])},methods:{p6eUnicode:v.n9}},S=D,b=o("../node_modules/vue-style-loader/index.js!../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/components/local/user-domains.vue?vue&type=style&index=0&id=67dd5324&prod&lang=scss&"),R=o("../node_modules/vue-loader/lib/runtime/componentNormalizer.js"),w=(0,R.Z)(S,a,l,!1,null,null,null),I=w.exports},"./js/pages/admin/users/index.vue":function(U,E,o){"use strict";o.r(E),o.d(E,{default:function(){return h}});var a=function(){var e=this,t=e._self._c;return t("app-page",{attrs:{actions:[{label:e.$gettext("Add New User"),icon:"add-new-user",handler:()=>e.$router.push("/reseller/create-user")}]},scopedSlots:e._u([{key:"default",fn:function(){return[t("app-page-section",[t("ui-api-table",e._b({on:{"action:message":function(s){e.$dialog("CREATE_MESSAGE_DIALOG").open()},"action:suspend":function(s){e.$dialog("SUSPEND_USER_DIALOG").open()},"action:unsuspend":e.unsuspendUsers,"action:del":function(s){e.$dialog("DELETE_ITEMS_DIALOG").open()}},scopedSlots:e._u([{key:"col:username",fn:function({username:s,suspended:g,deleted:_,remote_server:P,is_user:N,reason:u}){return[t("div",{staticClass:"wrap:nowrap"},[P?t("ui-link",{attrs:{href:`${e.options.remote_servers[P]}/CMD_SHOW_USER=${s}`,target:"_blank"}},[e._v(`
                            `+e._s(s)+`
                        `)]):t("ui-link",{attrs:{name:N?"reseller/users/view":"admin/users/resellers/view",params:{user:s}}},[e._v(`
                            `+e._s(s)+`
                        `)]),e._v(" "),g?t("ui-tooltip",{attrs:{theme:"danger",icon:"warning"}},[t("span",{domProps:{textContent:e._s(u?e.$gettextInterpolate(e.$gettext("Suspended: %{ reason }"),{reason:e.reasons[u]}):e.$gettext("Suspended"))}})]):e._e(),e._v(" "),_?t("ui-tooltip",{attrs:{theme:"danger",icon:"warning"}},[t("span",{domProps:{textContent:e._s(e.$gettext("Deleted"))}})]):e._e()],1)]}},{key:"col:creator",fn:function({creator:s}){return[s!=="root"?t("ui-link",{attrs:{name:"admin/users/resellers/view",params:{user:s}}},[e._v(`
                        `+e._s(s)+`
                    `)]):e._e()]}},{key:"col:bandwidth",fn:function({bandwidth:s}){return[t("ui-limited-usage",e._b({},"ui-limited-usage",s,!1))]}},{key:"col:quota",fn:function({quota:s}){return[t("ui-limited-usage",e._b({},"ui-limited-usage",s,!1))]}},{key:"col:vdomains",fn:function({vdomains:s}){return[t("ui-limited-usage",e._b({attrs:{plain:""}},"ui-limited-usage",s,!1))]}},{key:"col:mysql",fn:function({mysql:s}){return[t("ui-limited-usage",e._b({attrs:{plain:""}},"ui-limited-usage",s,!1))]}},{key:"col:ip",fn:function({ip:s}){return[s.length?e._e():t("span"),e._v(" "),e._l(s,function(g){return t("p",{directives:[{name:"margin",rawName:"v-margin",value:0,expression:"0"}],key:g},[e._v(`
                        `+e._s(g)+`
                    `)])})]}},{key:"col:domains",fn:function({domains:s}){return[t("user-domains",e._b({},"user-domains",{domains:s},!1))]}},{key:"col:sent_emails",fn:function({sent_emails:s}){return[e._v(`
                    `+e._s(e.getSentEmailsString(s))+`
                `)]}},{key:"col:date_created",fn:function({date_created:s}){return[e._v(`
                    `+e._s(e.date(s,"datetime"))+`
                `)]}},{key:"row:actions",fn:function({username:s,suspended:g}){return[t("ui-actions",[t("ui-link",{on:{click:function(_){e.select=[s],e.$dialog("CREATE_MESSAGE_DIALOG").open()}}},[t("span",{domProps:{textContent:e._s(e.$gettext("Send a Message"))}})]),e._v(" "),g?e._e():t("ui-link",{on:{click:function(_){e.select=[s],e.$dialog("SUSPEND_USER_DIALOG").open()}}},[t("span",{domProps:{textContent:e._s(e.$gettext("Suspend"))}})]),e._v(" "),g?t("ui-link",{on:{click:function(_){e.select=[s],e.unsuspendUsers()}}},[t("span",{domProps:{textContent:e._s(e.$gettext("Unsuspend"))}})]):e._e(),e._v(" "),t("ui-link",{on:{click:function(_){return e.loginAs(s)}}},[t("span",{domProps:{textContent:e._s(e.$gettextInterpolate(e.$gettext("Login as %{ username }"),{username:s}))}})]),e._v(" "),t("ui-link",{on:{click:function(_){return e.changePassword(s)}}},[t("span",{domProps:{textContent:e._s(e.$gettextInterpolate(e.$gettext("Change %{ username }'s password"),{username:s}))}})]),e._v(" "),t("ui-link",{on:{click:function(_){e.select=[s],e.$dialog("DELETE_ITEMS_DIALOG").open()}}},[t("span",{domProps:{textContent:e._s(e.$gettext("Remove"))}})])],1)]}}]),model:{value:e.select,callback:function(s){e.select=s},expression:"select"}},"ui-api-table",{command:e.$commands.getUsers,endpoint:"GET_ALL_USERS",property:"users",rowID:"username",columns:{username:{label:e.$gettext("Username"),searchable:!0},creator:{label:e.$gettext("Creator"),searchable:!0},bandwidth:{label:e.$gettext("Bandwidth"),getClass:s=>s.bandwidth.status?`--usage:${s.bandwidth.status}`:""},quota:{label:e.$gettext("Disk Usage"),getClass:s=>s.bandwidth.status?`--usage:${s.quota.status}`:""},vdomains:e.$gettext("# of domains"),domains:{label:e.$gettext("Domain(s)"),width:"minmax(15rem, auto)",searchable:!0},ip:{label:e.$gettext("IP(s)"),searchable:!0},suspended:{label:e.$gettext("Suspended"),hide:!0,searchable:{type:"select",options:{Yes:e.$gettext("Yes"),No:e.$gettext("No")}}},sent_emails:e.$gettext("Sent E-mails"),remote_server:{label:e.$gettext("Remote Server"),hide:!e.showRemoteServer},...e.additionalColumns},actions:{message:e.$gettext("Send a Message"),suspend:e.$gettext("Suspend"),unsuspend:e.$gettext("Unsuspend"),del:e.$gettext("Delete")},rowsMapper:e.mapUserStatus,rowsFilter:e.filterDeletedUsers},!1))],1),e._v(" "),t("create-message-dialog",{attrs:{users:e.select}}),e._v(" "),t("ui-dialog",{attrs:{id:"DELETE_ITEMS_DIALOG",title:e.$ngettext("Delete user","Delete users",e.select.length)},scopedSlots:e._u([{key:"content",fn:function(){return[t("ui-form-element",{attrs:{underline:!!e.deleteData.length},scopedSlots:e._u([{key:"content",fn:function(){return[t("span",{staticClass:"txt:bold",domProps:{textContent:e._s(e.$ngettext("Are you sure you want to delete selected user?","Are you sure you want to delete selected users?",e.select.length))}})]},proxy:!0}])}),e._v(" "),e.deleteData.length?t("ui-form-element",{attrs:{underline:e.options.add_leave_dns},scopedSlots:e._u([{key:"content",fn:function(){return[t("div",[t("table",{staticClass:"table-elem"},[t("tr",[t("th",{domProps:{textContent:e._s(e.$ngettext("You are deleting reseller that have users under control. If you proceed, these user accounts, along with ALL the associated website and email contents, which are not listed here, will also be removed.","You are deleting resellers that have users under control. If you proceed, these user accounts, along with ALL the associated website and email contents, which are not listed here, will also be removed.",e.deleteData.length))}})]),e._v(" "),e._l(e.deleteData,function(s){return t("tr",{key:s.name},[t("td",{domProps:{textContent:e._s(e.$gettextInterpolate(e.$ngettext("%{ name } and %{nusers } user","%{ name } and %{nusers } users",s.nusers),{name:s.name,nusers:s.nusers}))}})])})],2)])]},proxy:!0}],null,!1,2479592455)}):e._e(),e._v(" "),e.options.add_leave_dns?t("ui-form-element",{scopedSlots:e._u([{key:"content",fn:function(){return[t("input-checkbox",{model:{value:e.leaveDNS,callback:function(s){e.leaveDNS=s},expression:"leaveDNS"}},[t("span",{domProps:{textContent:e._s(e.$gettext("Leave DNS"))}}),e._v(" "),t("ui-tooltip",[t("span",{domProps:{textContent:e._s(e.$gettext("Do not remove DNS zones of domains owned by the user."))}})])],1)]},proxy:!0}],null,!1,3156043295)}):e._e()]},proxy:!0},{key:"buttons",fn:function(){return[t("ui-button",{attrs:{theme:"danger"},on:{click:e.deleteUsers}},[t("span",{domProps:{textContent:e._s(e.$gettext("Delete"))}})])]},proxy:!0}])}),e._v(" "),t("suspend-user-dialog",{attrs:{"api-reasons":e.$api.options.reasons.options},on:{suspend:e.suspendUsers}}),e._v(" "),t("change-password-dialog",{ref:"cpd"})]},proxy:!0}])})},l=[],p=o("../node_modules/ramda/es/index.js"),n=o("./js/api/commands/admin/users/index.js"),m=o("./js/api/commands/admin/users/actions.js"),v=o("./js/composables/filters.ts"),D=o("./js/components/local/create-message-dialog.vue"),S=o("./js/components/local/suspend-user-dialog.vue"),b=o("./js/components/local/user-domains.vue"),R=o("./js/components/local/change-user-password-dialog.vue"),w={preload:n.R,api:[{command:n.R,bind:{"response.users":"users","response.options":"options"}},{command:m.XB,bind:"usersPerReseller"}],commands:{getUsers:n.R},components:{CreateMessageDialog:D.Z,SuspendUserDialog:S.Z,UserDomains:b.Z,ChangePasswordDialog:R.Z},data(){return{select:[],leaveDNS:!1,message:"",userStatus:{}}},computed:{rows(){return this.$api.users.rows},options(){return this.$api.options},showRemoteServer(){return!!Object.keys(this.options.remote_servers||{}).length},reasons(){return S.Z.$exports.reasons.call(this,this.$api.options.reasons.options)},hasDateCreatedColumn(){return typeof this.$api.users.columns.date_created!="undefined"},additionalColumnLabels(){return{date_created:this.$gettext("Date Created"),mysql:this.$gettext("Databases"),package:this.$gettext("Package"),email:this.$gettext("E-mail")}},additionalColumns(){const r=["username","creator","bandwidth","quota","vdomains","suspended","ip","domains","sent_emails","remote_server"];return p.zGw(p.CEd(r),p.IDH((t,s)=>({label:this.additionalColumnLabels[s]||s,visible:!1})))(this.$api.users.columns)},deleteData(){return this.select.reduce((r,e)=>{const t=this.$api.usersPerReseller[e];return typeof t!="undefined"&&r.push({name:e,nusers:t}),r},[])}},mounted(){this.getUsersCountPerReseller(),this.options.connectionError&&this.$notifications.error({timeout:1/0,title:this.$gettext("Connection Error"),content:this.options.connectionError})},methods:{date:v.hT,getUsersCountPerReseller(){(0,m.XB)()},getUsageProgress(r){const e=r.usage*100/r.limit;let t="primary";return e>40&&(t="safe"),e>80&&(t="danger"),{size:"normal",theme:t,value:e}},async deleteUsers(){const{select:r}=this;(await(0,m.Vt)({select:r,leave_dns:this.options.add_leave_dns?this.leaveDNS:null},{manual:!0})).status!=500&&r.forEach(this.setStatus("deleted")),this.select=[],this.$reloadApiTable({reset:!1})},getChildUsers(r){return this.rows.filter(e=>e.creator===r).map(e=>e.username)},setStatus(r){return e=>this.$set(this.userStatus,e,r)},async suspendUsers(r){const{select:e}=this;if((await(0,m.f1)({select:e,...r},{manual:!0})).status!=500){const s=this.setStatus("suspended");e.forEach(g=>{s(g),this.getChildUsers(g).forEach(s)})}this.$reloadApiTable({reset:!1}),this.select=[]},async unsuspendUsers(){const{select:r}=this;if((await(0,m.Ss)({select:r},{manual:!0})).status!=500){const t=this.setStatus("active");r.forEach(s=>{t(s),this.getChildUsers(s).forEach(t)})}this.$reloadApiTable({reset:!1}),this.select=[]},filterDeletedUsers(r){return this.userStatus[r.username]!=="deleted"},mapUserStatus(r){return{...r,suspended:this.userStatus[r.username]?this.userStatus[r.username]==="suspended":r.suspended}},getSentEmailsString(r){const[e,t,s]=r.split(":");return t&&s?this.$gettextInterpolate(this.$gettext("%{ sent } (Today: %{ today } / %{ limit })"),{sent:e,today:t,limit:s}):e},loginAs(r){this.$_ctx.session.impersonateUser(r)},changePassword(r){this.$refs.cpd.show(r)}}},I=w,M=o("../node_modules/vue-loader/lib/runtime/componentNormalizer.js"),i=(0,M.Z)(I,a,l,!1,null,null,null),h=i.exports},"../node_modules/vue-style-loader/index.js!../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/components/local/user-domains.vue?vue&type=style&index=0&id=67dd5324&prod&lang=scss&":function(U,E,o){var a=o("../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/components/local/user-domains.vue?vue&type=style&index=0&id=67dd5324&prod&lang=scss&");a.__esModule&&(a=a.default),typeof a=="string"&&(a=[[U.id,a,""]]),a.locals&&(U.exports=a.locals);var l=o("../node_modules/vue-style-loader/lib/addStylesClient.js").Z,p=l("45c1543d",a,!0,{})}}]);