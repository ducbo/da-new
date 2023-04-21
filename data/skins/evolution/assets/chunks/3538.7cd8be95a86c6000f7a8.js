"use strict";(self.webpackChunk=self.webpackChunk||[]).push([[3538],{"./js/pages/user/login-keys/log.vue":function(b,n,e){e.r(n),e.d(n,{default:function(){return C}});var m=function(){var t=this,o=t._self._c,u=t._self._setupProxy;return o("app-page",[o("app-page-section",[o("ui-r-table",{attrs:{"is-checkable":!1,"is-sortable":!1,rows:t.loginHistory,columns:[{id:"time",label:t.$gettext("Date")},{id:"ip",label:t.$gettext("IP")},{id:"command",label:t.$gettext("Command"),grow:!0},{id:"result",label:t.$gettext("Status")}]},scopedSlots:t._u([{key:"col:time",fn:function({time:s}){return[o("span",{staticClass:"wrap:nowrap",domProps:{textContent:t._s(t.formatDateTime(s))}})]}}])})],1)],1)},g=[],d=e("./js/openapi/loginKeys.ts"),p=e("./js/composables/notify.ts"),c=e("./js/composables/gettext.ts"),l=e("../node_modules/vue/dist/vue.common.prod.js"),f=e("./js/pages/user/login-keys/utils.login-keys.ts");const a=(0,l.ref)([]),{$gettext:r}=(0,c.Z)();var v=(0,l.defineComponent)({async beforeRouteEnter(i,t,o){const{data:u,error:s}=await(0,d.g1)(i.params.keyname);if(s){(0,p.d$)().error({title:r("Login Keys"),content:r("Could not load login key history")}),o(!1);return}a.value=u,o()},setup(){return{loginHistory:a,formatDateTime:f.o0}}}),y=v,x=e("../node_modules/vue-loader/lib/runtime/componentNormalizer.js"),j=(0,x.Z)(y,m,g,!1,null,null,null),C=j.exports}}]);
