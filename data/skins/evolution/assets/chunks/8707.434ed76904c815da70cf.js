(self.webpackChunk=self.webpackChunk||[]).push([[8707],{"./js/api/commands/validation/index.js":function(A,E,s){"use strict";s.d(E,{i9:function(){return D},ty:function(){return g},l7:function(){return _},OE:function(){return d},ub:function(){return m},oH:function(){return R},U5:function(){return c},k_:function(){return j},PR:function(){return o},uo:function(){return h},Jj:function(){return P},rV:function(){return x}});var e=s("./js/api/command/index.js"),i=s("../node_modules/punycode/punycode.es6.js"),v=s("./js/api/commands/converters/index.ts"),y={isValid(t){return typeof t.error=="undefined"},getMessage(t){return(0,v.S8)(t.error||"")}};const n=e.Z.get({url:"/CMD_JSON_VALIDATE",schema:{value:e.Z.REQUIRED_STRING},response:{valid:!0,message:""},mapResponse:{valid:y.isValid,message:y.getMessage}}),j=n.extend({id:"VALIDATE_FORWARDER",params:{type:"forwarder",ignore_system_default:!0}}),R=n.extend({id:"VALIDATE_EMAIL",params:{type:"email",check_mailing_list:!0},schema:{check_exists:{type:Boolean,required:!1,default:!0}}}),c=n.extend({id:"VALIDATE_FTP",params:{type:"ftp"},domain:!0}),l=n.extend({params:{type:"dns"},domain:!0,schema:{record:e.Z.REQUIRED_STRING}}),_=l.extend({id:"VALIDATE_DNS_VALUE",params:{check:"value",name:!0},domain:!0,schema:{value:e.Z.REQUIRED_STRING}}),o=_.extend({id:"VALIDATE_MX_VALUE",params:{record:"MX"},before:({value:t})=>({value:"10",mx_value:t})}),g=l.extend({id:"VALIDATE_DNS_NAME",params:{check:"name",value:!0,mx_value:!0},schema:{name:e.Z.REQUIRED_STRING,value:null}}),d=n.extend({id:"VALIDATE_DATABASE",params:{type:"dbname"}}),D=n.extend({id:"VALIDATE_DATABASE_USER",params:{type:"dbusername"}}),x=n.extend({id:"VALIDATE_USERNAME",params:{type:"username"}}),P=n.extend({id:"VALIDATE_SUBDOMAIN",domain:!0,params:{type:"subdomain"}}),h=n.extend({id:"VALIDATE_PASSWORD",params:{type:"password"}}),m=n.extend({id:"VALIDATE_DOMAIN",params:{type:"domain"},before:({value:t})=>({value:i.ZP.toASCII(t)})}),p=n.extend({id:"VALIDATE_IP_RANGE_LIST",params:{type:"ip_range_list"}})},"../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/pages/user/wordpress/users.vue?vue&type=style&index=0&id=0d99f04d&prod&lang=scss&scoped=true&":function(){},"./js/api/commands/converters/customItems.ts":function(A,E,s){"use strict";s.d(E,{CR:function(){return n}});var e=s("../node_modules/ramda/es/index.js"),i=s("./js/api/commands/converters/index.ts"),v=s("./js/api/commands/utils/transduce.ts"),y=s("./js/api/commands/converters/toSelectData.ts");const n=c=>{const l={name:c.name,type:c.type==="listbox"?"select":c.type,label:c.string,description:c.desc||"",value:c.type==="checkbox"?(0,i.sw)(c.checked||"no"):c.value||""};return l.type==="select"?e.BPw(l,(0,y.M1)(c.select||{})):l},j=c=>(0,v.vr)([(0,v.uD)(l=>/^item\d+val$/.test(l)),(0,v.r5)(l=>{const _=l,o=l.replace("val","txt"),g=c[_],d=c[o];return{[g]:d}})],Object.keys(c)),R=(c,l)=>e.qCK(o=>{const g={name:o.name,type:o.type==="listbox"?"select":o.type,description:o.desc||"",value:o.value||"",label:o.string};return o.type==="listbox"?(g.value=o.default,g.options=j(o)):o.type==="checkbox"&&(g.value=o.checked==="yes"),g},e.BPw({name:c}),(0,v.vr)([(0,v.r5)(o=>{const[g,d]=e.Vl2("=",o);return{[g]:d}})]),e.Vl2("&"))(l);E.ZP={fromObject:n,fromString:R}},"./js/api/commands/converters/index.ts":function(A,E,s){"use strict";s.d(E,{l$:function(){return _.ZP},t0:function(){return e.t0},S8:function(){return e.S8},ql:function(){return e.ql},sw:function(){return e.sw},Qu:function(){return e.Qu},He:function(){return e.He},M1:function(){return l.M1},sf:function(){return g},cc:function(){return c}});var e=s("./js/api/commands/converters/primitive.ts"),i=s("../node_modules/monet/dist/monet.js"),v=s("./js/api/commands/types.ts");const y=d=>typeof d=="object"?i.Either.Right(d):i.Either.Left(new Error("Passed param is not an object")),n=d=>typeof d.usage=="string"?i.Either.Right(d):i.Either.Left(new Error("usage property is required")),j=d=>({usage:(0,e.He)(d.usage),limit:(0,e.Qu)(d.limit)}),R=({usage:d,limit:D})=>{let x=v.H.Normal;const P=Math.floor(d/D*100);return P>=100?x=v.H.OverUsed:P>80&&(x=v.H.AlmostUsed),{usage:d,limit:D,status:x}},c=d=>{const D=i.Either.Right(d).flatMap(y).flatMap(n).map(j).map(R);if(D.isLeft())throw D.left();return D.right()};var l=s("./js/api/commands/converters/toSelectData.ts"),_=s("./js/api/commands/converters/customItems.ts"),o=s("../node_modules/ramda/es/index.js");const g=d=>D=>{const{info:x}=D,P=o.CEd(["info"],D);return{columns:x.columns,rowsCount:Number(x.rows),rows:o.UID(d,o.VO0(P))}}},"./js/api/commands/converters/toSelectData.ts":function(A,E,s){"use strict";s.d(E,{M1:function(){return R}});var e=s("../node_modules/monet/dist/monet.js"),i=s.n(e),v=s("./js/api/commands/utils/transduce.ts"),y=s("../node_modules/ramda/es/index.js");const n=c=>e.Maybe.Some(c).flatMap(l=>{const _=l.find(o=>o.selected==="yes");return _?e.Maybe.Some(_):e.Maybe.None()}).flatMap(l=>e.Maybe.fromNull(l.value)).orSome(""),j=(0,v.vr)([(0,v.r5)(c=>({[c.value]:c.text}))]),R=c=>{const l=(0,y.VO0)(c);return{value:n(l),options:j(l)}}},"./js/api/commands/types.ts":function(A,E,s){"use strict";s.d(E,{H:function(){return e}});var e;(function(i){i.Normal="normal",i.AlmostUsed="almost_used",i.OverUsed="overused"})(e||(e={}))},"./js/api/commands/utils/transduce.ts":function(A,E,s){"use strict";s.d(E,{Re:function(){return y},r5:function(){return i},uD:function(){return v},vr:function(){return l},zh:function(){return R}});var e=s("../node_modules/ramda/es/index.js");const i=_=>o=>(g,d)=>{const D=_(d);return o(g,D)},v=_=>o=>(g,d)=>_(d)?o(g,d):g,y=(_,o)=>(_.push(o),_),n=(_,o)=>e.BPw(_,o),j=(_,o,g,d)=>{const D=e.qCK(...g);return d.reduce(D(o),_)},R=e.WAo(j),c=R([],y),l=R({},n)},"./js/composables/useDataStore.ts":function(A,E,s){"use strict";s.d(E,{a:function(){return y}});var e=s("./js/api/openapi/decorators/data-store-decorator.ts"),i=s("../node_modules/vue/dist/vue.common.prod.js"),v=s.n(i);const y=n=>{const j=(0,i.ref)(null);return{data:j,request:(0,e.i)(j,n)}}},"./js/openapi/wordpress.ts":function(A,E,s){"use strict";s.d(E,{FO:function(){return h},GY:function(){return g},RK:function(){return x},Rf:function(){return c},Sg:function(){return _},c0:function(){return d},cc:function(){return D},il:function(){return P},oi:function(){return l},s8:function(){return o}});var e=s("./js/api/openapi/index.ts"),i=s("../node_modules/runtypes/lib/index.js"),v=s.n(i),y=s("./js/openapi/web.types.ts");const n=(0,e.$d)(),j=e.an.Default(async(m,p)=>{const{data:t}=await n.get(`/api/wordpress/locations/${m}/options`,p);return t.status==="success"&&i.Dictionary(i.String).guard(t.data)===!1?n.failure({type:"INVALID_RESPONSE",response:t.data}):t}),R=e.an.Default(async(m,p,t)=>{const{data:f}=await n.patch(`/api/wordpress/locations/${m}/options`,p,t);return f.status==="success"&&i.Dictionary(i.String).guard(f.data)===!1?n.failure({type:"INVALID_RESPONSE",response:f.data}):f}),c=e.an.Default(async(m,p)=>{const{data:t}=await n.get(`/api/wordpress/locations/${m}/users`,p);return t.status==="success"&&i.Array(y.qD).guard(t.data)===!1?n.failure({type:"INVALID_RESPONSE",response:t.data}):t}),l=e.an.Default(async(m,p,t,f)=>{const{data:I}=await n.post(`/api/wordpress/locations/${m}/users/${p}/change-password`,t,f);return I}),_=e.an.Default(async(m,p,t)=>{const{data:f}=await n.post(`/api/wordpress/locations/${m}/users/${p}/sso-login`,t);return f.status==="success"&&y.Ns.guard(f.data)===!1?n.failure({type:"INVALID_RESPONSE",response:f.data}):f}),o=e.an.Default(async(m,p)=>{const{data:t}=await n.get(`/api/wordpress/locations/${m}/wordpress`,p);return t.status==="success"&&y.qV.guard(t.data)===!1?n.failure({type:"INVALID_RESPONSE",response:t.data}):t}),g=e.an.Default(async(m,p,t)=>{const{data:f}=await n.put(`/api/wordpress/locations/${m}/config/auto-update`,p,t);return f}),d=e.an.Default(async(m,p)=>{const{data:t}=await n.get(`/api/wordpress/locations/${m}/config`,p);return t.status==="success"&&y.FJ.guard(t.data)===!1?n.failure({type:"INVALID_RESPONSE",response:t.data}):t}),D=e.an.Default(async(m,p,t)=>{const{data:f}=await n.put(`/api/wordpress/locations/${m}/config`,p,t);return f.status==="success"&&y.FJ.guard(f.data)===!1?n.failure({type:"INVALID_RESPONSE",response:f.data}):f}),x=e.an.Default(async(m,p)=>{const{data:t}=await n.delete(`/api/wordpress/locations/${m}`,p);return t}),P=e.an.Default(async(m,p)=>{const{data:t}=await n.get("/api/wordpress/locations",Object.assign({},p||{},{params:m}));return t.status==="success"&&i.Array(y.ff).guard(t.data)===!1?n.failure({type:"INVALID_RESPONSE",response:t.data}):t}),h=e.an.Default(async(m,p)=>{const{data:t}=await n.post("/api/wordpress/install",m,p);return t})},"./js/pages/user/wordpress/users.vue":function(A,E,s){"use strict";s.r(E),s.d(E,{default:function(){return F}});var e=function(){var r=this,a=r._self._c,u=r._self._setupProxy;return a("app-page",{attrs:{id:"modify-userlist",actions:[{label:u.$gettext("Back to WordPress Manager"),icon:"#anchor",name:"user/wordpress"},{label:u.$gettext("WordPress Dashboard"),visible:u.wordpressInstance,icon:"#wordpress-dashboard",handler:()=>u.openInNewTab(u.wordpressInstance.siteURL+"/wp-login.php")}],"back-btn":!1},scopedSlots:r._u([{key:"default",fn:function(){return[a("app-page-section",[a("ui-r-table",{attrs:{rows:u.wordpressUsers,columns:[{id:"displayName",label:u.$gettext("Name")},{id:"email",label:u.$gettext("Email")},{id:"login",label:u.$gettext("Login")},{id:"registered",label:u.$gettext("Registered")},{id:"roles",label:u.$gettext("Roles")}],"is-checkable":!1,"hide-before-controls":!0},scopedSlots:r._u([{key:"col:displayName",fn:function({item:S}){return[r._v(`
                    `+r._s(S.displayName)+`
                    `),a("ui-link",{directives:[{name:"margin",rawName:"v-margin",value:[,,,1],expression:"[, , , 1]"}],attrs:{title:u.$gettext("Sign In as user")},on:{click:function(M){return u.generateMagicLogin(S)}}},[a("ui-icon",{attrs:{id:"webmail-sso",theme:"primary",size:"medium4"}})],1)]}},{key:"col:roles",fn:function({roles:S}){return[r._v(`
                    `+r._s(S.toString())+`
                `)]}},{key:"row:actions",fn:function({item:S}){return[a("ui-link",{attrs:{title:u.$gettext("Change Password")},on:{click:function(M){return u.beforeResetPassword(S)}}},[a("ui-icon",{attrs:{id:"keys",theme:"primary"}})],1)]}}])})],1),r._v(" "),a(u.ChangeWpUserPassDialog,{attrs:{id:r.id,user:u.currentItem||{}}})]},proxy:!0}])})},i=[],v=s("../node_modules/vue/dist/vue.common.prod.js"),y=function(){var r=this,a=r._self._c,u=r._self._setupProxy;return a("ui-dialog",r._g({attrs:{id:"CHANGE_WP_USER_PASS_DIALOG",title:u.$gettext("Change password")},scopedSlots:r._u([{key:"content",fn:function(){return[a("div",[a("ui-form-element",{attrs:{vertical:""},scopedSlots:r._u([{key:"title",fn:function(){return[a("span",{domProps:{textContent:r._s(u.$gettext("Username:"))}})]},proxy:!0},{key:"content",fn:function(){return[a("input-text",{attrs:{value:r.user.displayName,disabled:""}})]},proxy:!0}])}),r._v(" "),a("ui-form-element",{attrs:{group:"changePassword",validators:{required:!0,api:u.validatePassword},vertical:""},scopedSlots:r._u([{key:"title",fn:function(){return[a("span",{domProps:{textContent:r._s(u.$gettext("Password:"))}})]},proxy:!0},{key:"content",fn:function(){return[a("input-password",{attrs:{"show-generator":""},model:{value:u.passwd.password,callback:function(S){r.$set(u.passwd,"password",S)},expression:"passwd.password"}})]},proxy:!0}])})],1)]},proxy:!0},{key:"buttons",fn:function(){return[a("ui-button",{attrs:{theme:"primary","validate-group":"changePassword"},on:{click:u.submit}},[a("span",{domProps:{textContent:r._s(u.$gettext("Save"))}})])]},proxy:!0}])},r.$listeners))},n=[],j=s("./js/api/commands/validation/index.js"),R=s("./js/openapi/wordpress.ts"),c=s("./js/composables/useErrorMessages.ts"),l=s("./js/composables/index.ts"),_=(0,v.defineComponent)({__name:"change-wp-user-pass-dialog",props:{id:null,user:null},setup(w){const r=w,a=(0,c.L)({}),{$gettext:u}=(0,l.st)(),S=(0,v.ref)({password:""});return{__sfc:!0,notifyError:a,$gettext:u,props:r,passwd:S,submit:async()=>{const{error:O}=await(0,R.oi)(r.id,r.user.id,S.value);if(O){a(O);return}(0,l.d$)().success({title:u("Success"),content:u("User password changed successfully")}),S.value.password=""},validatePassword:j.uo}}}),o=_,g=s("../node_modules/vue-loader/lib/runtime/componentNormalizer.js"),d=(0,g.Z)(o,y,n,!1,null,null,null),D=d.exports,x=s("./js/vue-globals/helpers.js"),P=s("./js/composables/useDataStore.ts"),h=s("./js/composables/gettext.ts"),m=s("./js/composables/notify.ts");const{$gettext:p,$gettextInterpolate:t}=(0,h.Z)(),f=(0,m.d$)(),{data:I,request:U}=(0,P.a)(R.Rf),{data:N,request:T}=(0,P.a)(R.s8),C=async(w,r)=>{const a=await U(w,r);return a.status==="error"&&f.error({title:p("Error"),content:t(p("Failed to load %{subject}!"),{subject:p("wordpress users")})}),a},$=async(w,r)=>{const a=await T(w,r);return a.status==="error"&&f.error({title:p("Error"),content:t(p("Failed to load %{subject}!"),{subject:p("wordpress instance")})}),a},V=(0,v.defineComponent)({async beforeRouteEnter(w,r,a){if(await C(w.params.id),await $(w.params.id),!N)return a(!1);a()}});var W=(0,v.defineComponent)({...V,__name:"users",props:{id:null},setup(w){const r=w,{$gettext:a}=(0,l.st)(),u=(0,l.Rh)("CHANGE_WP_USER_PASS_DIALOG"),S=(0,v.ref)(null);return{__sfc:!0,$gettext:a,changePasswordDialog:u,props:r,currentItem:S,generateMagicLogin:async L=>{const{data:b}=await(0,R.Sg)(r.id,L.id);b&&(0,x.YQ)(b.url)},beforeResetPassword:L=>{S.value=L,u.open()},ChangeWpUserPassDialog:D,openInNewTab:x.YQ,wordpressUsers:I,wordpressInstance:N}}}),B=W,Z=s("../node_modules/vue-style-loader/index.js!../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/pages/user/wordpress/users.vue?vue&type=style&index=0&id=0d99f04d&prod&lang=scss&scoped=true&"),K=(0,g.Z)(B,e,i,!1,null,"0d99f04d",null),F=K.exports},"../node_modules/vue-style-loader/index.js!../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/pages/user/wordpress/users.vue?vue&type=style&index=0&id=0d99f04d&prod&lang=scss&scoped=true&":function(A,E,s){var e=s("../node_modules/mini-css-extract-plugin/dist/loader.js??clonedRuleSet-13.use[1]!../node_modules/css-loader/dist/cjs.js??clonedRuleSet-13.use[2]!../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../node_modules/postcss-loader/dist/cjs.js??clonedRuleSet-13.use[3]!../node_modules/sass-loader/dist/cjs.js??clonedRuleSet-13.use[4]!../node_modules/vue-loader/lib/index.js??vue-loader-options!../node_modules/unplugin/dist/webpack/loaders/transform.js?unpluginName=unplugin-vue-define-options!./js/pages/user/wordpress/users.vue?vue&type=style&index=0&id=0d99f04d&prod&lang=scss&scoped=true&");e.__esModule&&(e=e.default),typeof e=="string"&&(e=[[A.id,e,""]]),e.locals&&(A.exports=e.locals);var i=s("../node_modules/vue-style-loader/lib/addStylesClient.js").Z,v=i("78c4d018",e,!0,{})}}]);