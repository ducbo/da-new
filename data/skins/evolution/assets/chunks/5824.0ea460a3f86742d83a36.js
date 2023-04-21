"use strict";(self.webpackChunk=self.webpackChunk||[]).push([[5824],{"./js/pages/user/email/catch-all.vue":function(v,r,o){o.r(r),o.d(r,{default:function(){return f}});var l=function(){var e=this,t=e._self._c;return t("app-page",{scopedSlots:e._u([{key:"details",fn:function(){return[t("ui-infobar-item",{attrs:{title:e.$gettext("Details")}},[t("span",{domProps:{textContent:e._s(e.$gettext("This e-mail address will catch all improperly addressed mail (i.e. to a user that doesn't exist) to your site. This address may be your defaultusername@yourdomain.com, or any other email account you have created."))}})])]},proxy:!0},{key:"default",fn:function(){return[e.$_layout!=="standard2021"?t("app-page-section",[t("span",{domProps:{textContent:e._s(e.$gettext("This e-mail address will catch all improperly addressed mail (i.e. to a user that doesn't exist) to your site. This address may be your defaultusername@yourdomain.com, or any other email account you have created."))}})]):e._e(),e._v(" "),t("app-page-section",[t("ui-form-element",{scopedSlots:e._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("Fail:"))}})]},proxy:!0},{key:"content",fn:function(){return[t("input-radio",{attrs:{value:":fail:"},model:{value:e.mode,callback:function(s){e.mode=s},expression:"mode"}},[t("span",[t("span",{domProps:{textContent:e._s(e.$gettext("The sender is notified that the address doesn't exist"))}}),e._v(" "),t("ui-tooltip",{attrs:{theme:"safe"}},[t("span",{domProps:{textContent:e._s(e.$gettext("This is the recommended option for the catch-all setting. Catch-all's will increase the server load due to spam, so having them disable is highly recommended unless you absolutely need the feature on."))}})])],1)])]},proxy:!0}])}),e._v(" "),t("ui-form-element",{scopedSlots:e._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("Ignore:"))}})]},proxy:!0},{key:"content",fn:function(){return[t("input-radio",{attrs:{value:":blackhole:"},model:{value:e.mode,callback:function(s){e.mode=s},expression:"mode"}},[t("span",[t("span",{domProps:{textContent:e._s(e.$gettext("The e-mail is dropped and completely ignored"))}}),e._v(" "),t("ui-tooltip",{attrs:{theme:"danger"}},[t("span",{domProps:{textContent:e._s(e.$gettext("Avoid using the Ignore option unless you know what you are doing. Spammers will be sending you e-mails to random addresses, and this option will accept those e-mails. You will not know it because the accepted e-mails would be discarded. This greatly increases the server load unnecessarily. If you do not want the catch-all to be on, then use the Fail option instead."))}})])],1)])]},proxy:!0}])}),e._v(" "),t("ui-form-element",{attrs:{underline:!1},scopedSlots:e._u([{key:"title",fn:function(){return[t("span",{domProps:{textContent:e._s(e.$gettext("Address:"))}})]},proxy:!0},{key:"content",fn:function(){return[t("input-radio",{attrs:{value:"address"},model:{value:e.mode,callback:function(s){e.mode=s},expression:"mode"}},[t("input-autocomplete",{attrs:{disabled:e.mode!=="address",values:e.addresses},on:{focus:function(s){e.mode="address"}},model:{value:e.value,callback:function(s){e.value=s},expression:"value"}})],1)]},proxy:!0}])})],1)]},proxy:!0},{key:"footer:buttons",fn:function(){return[t("ui-button",{attrs:{theme:"safe",disabled:e.mode==="address"&&!e.value},on:{click:e.saveOptions}},[t("span",{domProps:{textContent:e._s(e.$gettext("Save"))}})])]},proxy:!0}])})},d=[],n=o("./js/api/command/index.js");const i=n.Z.get({id:"CATCHALL_SETTINGS",url:"/CMD_EMAIL_CATCH_ALL",domain:!0,after:a=>a.flow(a.moveProp({poplist:"addresses",value:"mode"}),e=>({...e,value:[":fail:",":blackhole:"].includes(e.mode)?"":e.mode,mode:[":fail:",":blackhole:"].includes(e.mode)?e.mode:"address"}),a.mapProps({addresses:a.flow(a.toArray,e=>e.map(t=>t.value),e=>e.filter(t=>t),e=>e.map(t=>({value:t,label:t})))}))}),u=n.Z.post({url:"/CMD_EMAIL_CATCH_ALL",method:"POST",params:{update:!0},domain:!0,body:{value:n.Z.OPTIONAL_STRING,catch:{...n.Z.REQUIRED_STRING,validator:a=>[":fail:",":blackhole:","address"].includes(a)}}});var m={preload:i,api:[{command:i,bind:"settings"}],data(){return{mode:":fail:",value:""}},computed:{addresses(){return this.$api.settings.addresses.map(({value:a})=>a.includes("@")?this.$p6e.email2unicode(a):`${a}@${this.$domainUnicode}`)},requestDataValue(){return this.getEmails(this.value,this.$p6e.email2ascii)}},watch:{$domain:{async handler(){await i(),this.mode=this.$api.settings.mode,this.value=this.getEmails(this.$api.settings.value,this.$p6e.email2unicode)}}},created(){this.mode=this.$api.settings.mode,this.value=this.getEmails(this.$api.settings.value,this.$p6e.email2unicode)},methods:{async saveOptions(){await u({catch:this.mode,value:this.requestDataValue})},getEmails(a,e){return a.includes(",")?a.split(",").map(t=>t.trim()).filter(Boolean).map(e).join(","):a}}},c=m,p=o("../node_modules/vue-loader/lib/runtime/componentNormalizer.js"),h=(0,p.Z)(c,l,d,!1,null,null,null),f=h.exports}}]);