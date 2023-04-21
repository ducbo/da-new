(self.webpackChunk=self.webpackChunk||[]).push([[2736],{"./js/api/commands/admin/users/actions.js":function(y,_,s){"use strict";s.d(_,{Ss:function(){return f},Vt:function(){return r},XB:function(){return o},f1:function(){return l},uV:function(){return g},vk:function(){return m}});var t=s("./js/api/command/index.js");const i=t.Z.post({url:"/CMD_SELECT_USERS",notifySuccess:!0,notifyError:!0,params:{location:"CMD_ALL_USER_SHOW"},schema:{select:t.Z.ROWS},blocking:!0}),l=i.extend({params:{dosuspend:!0},schema:{reason:t.Z.REQUIRED_STRING},blocking:!0}),f=i.extend({params:{dounsuspend:!0},blocking:!0}),r=i.extend({params:{delete:!0,confirmed:!0},schema:{leave_dns:t.Z.OPTIONAL_BOOL},blocking:!0}),g=t.Z.post({url:"/CMD_ACCOUNT_ADMIN",params:{action:"create"},schema:{username:t.Z.REQUIRED_STRING,email:t.Z.REQUIRED_STRING,passwd:t.Z.REQUIRED_STRING,passwd2:t.Z.REQUIRED_STRING,notify:t.Z.REQUIRED_BOOL}}),m=t.Z.post({url:"/CMD_COMMENTS",params:{location:"CMD_SHOW_RESELLER"},schema:{user:t.Z.REQUIRED_STRING,comments:t.Z.REQUIRED_STRING}}),o=t.Z.post({url:"/CMD_MOVE_USERS",id:"USERS_COUNT_PER_RESELLER",response:{},after:d=>d.flow(d.getProp("data_list"),d.mapValues(c=>c.length))})},"./js/api/commands/admin/users/message.js":function(y,_,s){"use strict";s.d(_,{FC:function(){return f},TB:function(){return g},o6:function(){return r}});var t=s("./js/api/command/index.js");const i=({level:m})=>`/CMD_EDIT_${m.toUpperCase()}_MESSAGE`,l={type:String,required:!0,default:"reseller",validator:m=>["admin","reseller"].includes(m)},f=t.Z.get({id:"MESSAGE",url:i,schema:{level:l},after:m=>m.mapProp("message",m.convert.toAppText)}),r=t.Z.post({url:i,params:{save:!0},schema:{level:l,subject:t.Z.REQUIRED_STRING,message:t.Z.REQUIRED_STRING}}),g=t.Z.post({url:i,params:{reset:!0},schema:{level:l}})},"./js/api/commands/validation/index.js":function(y,_,s){"use strict";s.d(_,{i9:function(){return v},ty:function(){return p},l7:function(){return c},OE:function(){return u},ub:function(){return S},oH:function(){return m},U5:function(){return o},k_:function(){return g},PR:function(){return n},uo:function(){return R},Jj:function(){return j},rV:function(){return x}});var t=s("./js/api/command/index.js"),i=s("../node_modules/punycode/punycode.es6.js"),l=s("./js/api/commands/converters/index.ts"),f={isValid(e){return typeof e.error=="undefined"},getMessage(e){return(0,l.S8)(e.error||"")}};const r=t.Z.get({url:"/CMD_JSON_VALIDATE",schema:{value:t.Z.REQUIRED_STRING},response:{valid:!0,message:""},mapResponse:{valid:f.isValid,message:f.getMessage}}),g=r.extend({id:"VALIDATE_FORWARDER",params:{type:"forwarder",ignore_system_default:!0}}),m=r.extend({id:"VALIDATE_EMAIL",params:{type:"email",check_mailing_list:!0},schema:{check_exists:{type:Boolean,required:!1,default:!0}}}),o=r.extend({id:"VALIDATE_FTP",params:{type:"ftp"},domain:!0}),d=r.extend({params:{type:"dns"},domain:!0,schema:{record:t.Z.REQUIRED_STRING}}),c=d.extend({id:"VALIDATE_DNS_VALUE",params:{check:"value",name:!0},domain:!0,schema:{value:t.Z.REQUIRED_STRING}}),n=c.extend({id:"VALIDATE_MX_VALUE",params:{record:"MX"},before:({value:e})=>({value:"10",mx_value:e})}),p=d.extend({id:"VALIDATE_DNS_NAME",params:{check:"name",value:!0,mx_value:!0},schema:{name:t.Z.REQUIRED_STRING,value:null}}),u=r.extend({id:"VALIDATE_DATABASE",params:{type:"dbname"}}),v=r.extend({id:"VALIDATE_DATABASE_USER",params:{type:"dbusername"}}),x=r.extend({id:"VALIDATE_USERNAME",params:{type:"username"}}),j=r.extend({id:"VALIDATE_SUBDOMAIN",domain:!0,params:{type:"subdomain"}}),R=r.extend({id:"VALIDATE_PASSWORD",params:{type:"password"}}),S=r.extend({id:"VALIDATE_DOMAIN",params:{type:"domain"},before:({value:e})=>({value:i.ZP.toASCII(e)})}),D=r.extend({id:"VALIDATE_IP_RANGE_LIST",params:{type:"ip_range_list"}})},"../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/components/local/edit-admin-message-dialog.vue?vue&type=style&index=0&id=54f6af98&prod&lang=scss&scoped=true&":function(){},"./js/api/commands/converters/customItems.ts":function(y,_,s){"use strict";s.d(_,{CR:function(){return r}});var t=s("../node_modules/ramda/es/index.js"),i=s("./js/api/commands/converters/index.ts"),l=s("./js/api/commands/utils/transduce.ts"),f=s("./js/api/commands/converters/toSelectData.ts");const r=o=>{const d={name:o.name,type:o.type==="listbox"?"select":o.type,label:o.string,description:o.desc||"",value:o.type==="checkbox"?(0,i.sw)(o.checked||"no"):o.value||""};return d.type==="select"?t.BPw(d,(0,f.M1)(o.select||{})):d},g=o=>(0,l.vr)([(0,l.uD)(d=>/^item\d+val$/.test(d)),(0,l.r5)(d=>{const c=d,n=d.replace("val","txt"),p=o[c],u=o[n];return{[p]:u}})],Object.keys(o)),m=(o,d)=>t.qCK(n=>{const p={name:n.name,type:n.type==="listbox"?"select":n.type,description:n.desc||"",value:n.value||"",label:n.string};return n.type==="listbox"?(p.value=n.default,p.options=g(n)):n.type==="checkbox"&&(p.value=n.checked==="yes"),p},t.BPw({name:o}),(0,l.vr)([(0,l.r5)(n=>{const[p,u]=t.Vl2("=",n);return{[p]:u}})]),t.Vl2("&"))(d);_.ZP={fromObject:r,fromString:m}},"./js/api/commands/converters/index.ts":function(y,_,s){"use strict";s.d(_,{l$:function(){return c.ZP},t0:function(){return t.t0},S8:function(){return t.S8},ql:function(){return t.ql},sw:function(){return t.sw},Qu:function(){return t.Qu},He:function(){return t.He},M1:function(){return d.M1},sf:function(){return p},cc:function(){return o}});var t=s("./js/api/commands/converters/primitive.ts"),i=s("../node_modules/monet/dist/monet.js"),l=s("./js/api/commands/types.ts");const f=u=>typeof u=="object"?i.Either.Right(u):i.Either.Left(new Error("Passed param is not an object")),r=u=>typeof u.usage=="string"?i.Either.Right(u):i.Either.Left(new Error("usage property is required")),g=u=>({usage:(0,t.He)(u.usage),limit:(0,t.Qu)(u.limit)}),m=({usage:u,limit:v})=>{let x=l.H.Normal;const j=Math.floor(u/v*100);return j>=100?x=l.H.OverUsed:j>80&&(x=l.H.AlmostUsed),{usage:u,limit:v,status:x}},o=u=>{const v=i.Either.Right(u).flatMap(f).flatMap(r).map(g).map(m);if(v.isLeft())throw v.left();return v.right()};var d=s("./js/api/commands/converters/toSelectData.ts"),c=s("./js/api/commands/converters/customItems.ts"),n=s("../node_modules/ramda/es/index.js");const p=u=>v=>{const{info:x}=v,j=n.CEd(["info"],v);return{columns:x.columns,rowsCount:Number(x.rows),rows:n.UID(u,n.VO0(j))}}},"./js/api/commands/converters/toSelectData.ts":function(y,_,s){"use strict";s.d(_,{M1:function(){return m}});var t=s("../node_modules/monet/dist/monet.js"),i=s.n(t),l=s("./js/api/commands/utils/transduce.ts"),f=s("../node_modules/ramda/es/index.js");const r=o=>t.Maybe.Some(o).flatMap(d=>{const c=d.find(n=>n.selected==="yes");return c?t.Maybe.Some(c):t.Maybe.None()}).flatMap(d=>t.Maybe.fromNull(d.value)).orSome(""),g=(0,l.vr)([(0,l.r5)(o=>({[o.value]:o.text}))]),m=o=>{const d=(0,f.VO0)(o);return{value:r(d),options:g(d)}}},"./js/api/commands/types.ts":function(y,_,s){"use strict";s.d(_,{H:function(){return t}});var t;(function(i){i.Normal="normal",i.AlmostUsed="almost_used",i.OverUsed="overused"})(t||(t={}))},"./js/api/commands/utils/transduce.ts":function(y,_,s){"use strict";s.d(_,{Re:function(){return f},r5:function(){return i},uD:function(){return l},vr:function(){return d},zh:function(){return m}});var t=s("../node_modules/ramda/es/index.js");const i=c=>n=>(p,u)=>{const v=c(u);return n(p,v)},l=c=>n=>(p,u)=>c(u)?n(p,u):p,f=(c,n)=>(c.push(n),c),r=(c,n)=>t.BPw(c,n),g=(c,n,p,u)=>{const v=t.qCK(...p);return u.reduce(v(n),c)},m=t.WAo(g),o=m([],f),d=m({},r)},"./js/pages/admin/users/create-admin.vue":function(y,_,s){"use strict";s.r(_),s.d(_,{default:function(){return S}});var t=function(){var e=this,a=e._self._c;return a("app-page",{attrs:{actions:[{label:e.$gettext("Edit Admin Message"),icon:"#pencil",handler:e.editAdminMessage,theme:"safe"}]},scopedSlots:e._u([{key:"default",fn:function(){return[a("app-page-section",[a("ui-form-element",{attrs:{group:"createAdmin",validators:{required:!0,api:e.$commands.validateUsername}},scopedSlots:e._u([{key:"title",fn:function(){return[a("span",{domProps:{textContent:e._s(e.$gettext("Username"))}})]},proxy:!0},{key:"content",fn:function(){return[a("input-text",{model:{value:e.username,callback:function(E){e.username=E},expression:"username"}})]},proxy:!0}])}),e._v(" "),a("ui-form-element",{attrs:{group:"createAdmin",validators:{required:!0,regex:e.regexps.email}},scopedSlots:e._u([{key:"title",fn:function(){return[a("span",{domProps:{textContent:e._s(e.$gettext("E-mail"))}})]},proxy:!0},{key:"content",fn:function(){return[a("input-text",{model:{value:e.email,callback:function(E){e.email=E},expression:"email"}})]},proxy:!0},{key:"error:regex",fn:function(){return[a("span",{domProps:{textContent:e._s(e.$gettext("Should be valid email"))}})]},proxy:!0}])}),e._v(" "),a("ui-form-element",{attrs:{group:"createAdmin",validators:{required:!0,api:e.$commands.validatePassword}},scopedSlots:e._u([{key:"title",fn:function(){return[a("span",{domProps:{textContent:e._s(e.$gettext("Enter Password"))}})]},proxy:!0},{key:"content",fn:function(){return[a("input-password",{attrs:{"show-generator":""},model:{value:e.passwd,callback:function(E){e.passwd=E},expression:"passwd"}})]},proxy:!0}])}),e._v(" "),a("ui-form-element",{scopedSlots:e._u([{key:"title",fn:function(){return[a("span")]},proxy:!0},{key:"content",fn:function(){return[a("input-checkbox",{model:{value:e.notify,callback:function(E){e.notify=E},expression:"notify"}},[a("span",{domProps:{textContent:e._s(e.$gettext("Send E-mail Notification"))}})])]},proxy:!0}])})],1),e._v(" "),a("edit-admin-message-dialog")]},proxy:!0},{key:"footer:buttons",fn:function(){return[a("ui-button",{attrs:{theme:"safe","validate-group":"createAdmin"},on:{click:e.createAdmin}},[a("span",{domProps:{textContent:e._s(e.$gettext("Create"))}})])]},proxy:!0}])})},i=[],l=s("./js/api/commands/validation/index.js"),f=s("./js/api/commands/admin/users/actions.js"),r=s("./js/api/commands/admin/users/message.js"),g=s("./js/modules/constants.js"),m=function(){var e=this,a=e._self._c;return a("ui-dialog",{attrs:{id:"EDIT_ADMIN_MESSAGE_DIALOG",size:"normal","no-close-btn":"",title:e.$gettext("Edit E-mail Message")},on:{"dialog:open":e.loadData},scopedSlots:e._u([{key:"content",fn:function(){return[a("ui-form-element",{attrs:{vertical:""},scopedSlots:e._u([{key:"title",fn:function(){return[a("span",{domProps:{textContent:e._s(e.$gettext("Subject"))}})]},proxy:!0},{key:"content",fn:function(){return[a("input",{directives:[{name:"model",rawName:"v-model",value:e.subject,expression:"subject"}],attrs:{type:"text"},domProps:{value:e.subject},on:{input:function(E){E.target.composing||(e.subject=E.target.value)}}})]},proxy:!0}])}),e._v(" "),a("ui-form-element",{attrs:{vertical:""},scopedSlots:e._u([{key:"title",fn:function(){return[a("span",{domProps:{textContent:e._s(e.$gettext("Message"))}})]},proxy:!0},{key:"content",fn:function(){return[a("textarea",{directives:[{name:"model",rawName:"v-model",value:e.message,expression:"message"}],domProps:{value:e.message},on:{input:function(E){E.target.composing||(e.message=E.target.value)}}})]},proxy:!0}])})]},proxy:!0},{key:"buttons",fn:function(){return[a("ui-button",{attrs:{theme:"safe"},on:{click:e.updateMessage}},[a("span",{domProps:{textContent:e._s(e.$gettext("Save"))}})]),e._v(" "),a("ui-button",{attrs:{theme:"danger"},on:{click:e.resetMessage}},[a("span",{domProps:{textContent:e._s(e.$gettext("Reset"))}})])]},proxy:!0}])})},o=[],d={api:[{command:r.FC,bind:"message"}],data(){return{message:"",subject:""}},methods:{loadData(){Object.assign(this,this.$api.message)},async updateMessage(){r.o6({level:"admin",subject:this.subject,message:this.message})},async resetMessage(){await r.TB({level:"admin"}),Object.assign(this,await r.FC({level:"admin"}))}}},c=d,n=s("../node_modules/vue-style-loader/index.js!../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/components/local/edit-admin-message-dialog.vue?vue&type=style&index=0&id=54f6af98&prod&lang=scss&scoped=true&"),p=s("../node_modules/vue-loader/lib/runtime/componentNormalizer.js"),u=(0,p.Z)(c,m,o,!1,null,"54f6af98",null),v=u.exports,x={commands:{validateUsername:l.rV,validatePassword:l.uo},components:{EditAdminMessageDialog:v},data(){return{username:"",passwd:"",email:"",notify:!1}},created(){this.regexps=g.gk},methods:{async editAdminMessage(){await(0,r.FC)({level:"admin"}),this.$dialog("EDIT_ADMIN_MESSAGE_DIALOG").open()},async createAdmin(){await(0,f.uV)({username:this.username,email:this.email,passwd:this.passwd,passwd2:this.passwd,notify:this.notify})&&this.$router.push({name:"admin/users/admins"})}}},j=x,R=(0,p.Z)(j,t,i,!1,null,null,null),S=R.exports},"../node_modules/vue-style-loader/index.js!../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/components/local/edit-admin-message-dialog.vue?vue&type=style&index=0&id=54f6af98&prod&lang=scss&scoped=true&":function(y,_,s){var t=s("../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/components/local/edit-admin-message-dialog.vue?vue&type=style&index=0&id=54f6af98&prod&lang=scss&scoped=true&");t.__esModule&&(t=t.default),typeof t=="string"&&(t=[[y.id,t,""]]),t.locals&&(y.exports=t.locals);var i=s("../node_modules/vue-style-loader/lib/addStylesClient.js").Z,l=i("e23a6b0c",t,!0,{})}}]);
