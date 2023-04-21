"use strict";(self.webpackChunk=self.webpackChunk||[]).push([[7570],{"./js/pages/user/php-settings/index.vue":function(C,o,u){u.r(o),u.d(o,{default:function(){return V}});var c=function(){var t=this,e=t._self._c;return e("app-page",{scopedSlots:t._u([{key:"default",fn:function(){return[t.data.length?e("app-page-section",{scopedSlots:t._u([{key:"footer:buttons",fn:function(){return[e("ui-button",{attrs:{theme:"safe"},on:{click:t.saveSettings}},[e("span",{domProps:{textContent:t._s(t.$gettext("Save"))}})])]},proxy:!0}],null,!1,1791480593)},[e("ui-table",{attrs:{items:t.data}},[e("ui-column",{attrs:{id:"name",label:t.$gettext("Setting"),fit:""},scopedSlots:t._u([{key:"default",fn:function({name:a}){return[e("strong",{domProps:{textContent:t._s(a)}})]}}],null,!1,1832901191)}),t._v(" "),e("ui-column",{attrs:{id:"value",label:t.$gettext("Value")},scopedSlots:t._u([{key:"default",fn:function(a){return[e("setting-input",t._b({key:a.name,model:{value:a.value,callback:function(d){t.$set(a,"value",d)},expression:"item.value"}},"setting-input",t.$api.template[a.name],!1))]}}],null,!1,1771075036)}),t._v(" "),e("ui-column",{attrs:{id:"button",fit:""},scopedSlots:t._u([{key:"default",fn:function({name:a}){return[e("ui-button",{attrs:{theme:"danger",size:"normal",icon:"delete"},on:{click:function(d){return t.deleteSetting(a)}}},[e("span",{domProps:{textContent:t._s(t.$gettext("Delete"))}})])]}}],null,!1,2783241905)})],1)],1):t._e(),t._v(" "),t.availableSettings.length?e("app-page-section",{scopedSlots:t._u([{key:"section:title",fn:function(){return[e("span",{domProps:{textContent:t._s(t.$gettext("Add New Override"))}})]},proxy:!0},{key:"footer:buttons",fn:function(){return[e("ui-button",{attrs:{size:"normal",theme:"safe"},on:{click:function(a){return t.addOverride(t.key)}}},[e("span",{domProps:{textContent:t._s(t.$gettext("Add"))}})])]},proxy:!0}],null,!1,415183413)},[t._v(" "),e("ui-form-element",{scopedSlots:t._u([{key:"title",fn:function(){return[e("span",{domProps:{textContent:t._s(t.$gettext("Setting"))}})]},proxy:!0},{key:"content",fn:function(){return[e("input-select",{attrs:{options:Object.keys(t.$api.template),"disabled-options":t.overridenSettings},model:{value:t.key,callback:function(a){t.key=a},expression:"key"}})]},proxy:!0}],null,!1,246196165)}),t._v(" "),e("ui-form-element",{scopedSlots:t._u([{key:"title",fn:function(){return[e("span",{domProps:{textContent:t._s(t.$gettext("Value"))}})]},proxy:!0},{key:"content",fn:function(){return[t.key?e("setting-input",t._b({model:{value:t.defaults[t.key],callback:function(a){t.$set(t.defaults,t.key,a)},expression:"defaults[key]"}},"setting-input",t.$api.template[t.key],!1)):t._e()]},proxy:!0}],null,!1,2191748893)})],1):t._e()]},proxy:!0}])})},f=[],s=u("../node_modules/ramda/es/index.js"),i=u("./js/api/command/index.js");const l="/CMD_PHP_SETTINGS",r=i.Z.get({id:"PHP_SETTINGS",url:l,domain:!0,mapResponse:{template:n=>n.template_php_ini,data:n=>n.domain_php_ini}}),v=i.Z.post({url:l,domain:!0,params:{action:"add"}}),g=i.Z.select({url:l,params:{action:"delete"},domain:!0});var m=function(){var t=this,e=t._self._c;return t.type==="bool"?e("input-select",{attrs:{options:{On:t.$gettext("On"),Off:t.$gettext("Off")}},model:{value:t.dataValue,callback:function(a){t.dataValue=a},expression:"dataValue"}}):t.type==="list"?e("input-select",{attrs:{options:t.values},model:{value:t.dataValue,callback:function(a){t.dataValue=a},expression:"dataValue"}}):t.type==="int"?e("input-text",{staticClass:"width:100%",attrs:{number:""},model:{value:t.dataValue,callback:function(a){t.dataValue=a},expression:"dataValue"}}):e("input-text",{staticClass:"width:100%",model:{value:t.dataValue,callback:function(a){t.dataValue=a},expression:"dataValue"}})},_=[],h={model:{prop:"value",event:"change"},props:{type:{type:String,required:!0},value:{type:String,default:"",required:!1},values:{type:Array,default:()=>[],required:!1}},data(){return{dataValue:this.value}},watch:{value(n){n!==this.dataValue&&(this.dataValue=n)},dataValue(n){n!==this.value&&this.$emit("change",n)}}},y=h,p=u("../node_modules/vue-loader/lib/runtime/componentNormalizer.js"),x=(0,p.Z)(y,m,_,!1,null,null,null),S=x.exports,k={preload:r,api:r,components:{SettingInput:S},data(){return{defaults:{},data:[],key:""}},computed:{overridenSettings(){return s.UID(s.vgT("name"),this.data)},availableSettings(){return s.zud(this.overridenSettings,s.XPQ(this.$api.template))},requestData(){return this.data.reduce((n,{name:t,value:e})=>({...n,[t]:e,[`save_${t}`]:e}),{})}},created(){this.updateData()},methods:{updateData(){Object.entries(this.$api.template).forEach(([n,t])=>this.$set(this.defaults,n,t.default.toString())),this.data=s.UID(([n,t])=>({name:n,value:t}),s.Zpf(this.$api.data)),this.$nextTick(this.updateKey)},addOverride(n){this.data.push({name:n,value:this.defaults[n]}),this.saveSettings().then(this.getSettings)},saveSettings(){return v(this.requestData)},updateKey(){this.key=this.availableSettings[0]},getSettings(){return r().then(this.updateData)},deleteSetting(n){return g({select:[n]}).then(this.getSettings)}}},b=k,$=(0,p.Z)(b,c,f,!1,null,null,null),V=$.exports}}]);