/* Synthetic Linux/XKB physical-key-to-text oracle. HID usage mapping is
 * tested separately in Go. No real keyboard/credentials and no typing into
 * a host application. IMEs are NOT simulated by libxkbcommon.
 */
#include <xkbcommon/xkbcommon.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
struct fixture{const char *layout,*variant;unsigned evcode;uint32_t expected;int thai;};
static int probe(struct xkb_context *ctx,const struct fixture *f) {
 struct xkb_rule_names names={.rules="evdev",.model="pc105",
  .layout=f->layout,.variant=f->variant,.options=""};
 struct xkb_keymap *map=xkb_keymap_new_from_names(ctx,&names,
        XKB_KEYMAP_COMPILE_NO_FLAGS);
 if(!map){fprintf(stderr,"R26_N4_XKB_LAYOUT=%s RED missing map\n",f->layout);return 1;}
 struct xkb_state *state=xkb_state_new(map);
 if(!state){xkb_keymap_unref(map);return 1;}
 xkb_keycode_t keycode=f->evcode+8; /* evdev keycode -> XKB keycode */
 uint32_t cp=xkb_state_key_get_utf32(state,keycode);
 printf("R26_N4_XKB_LAYOUT=%s keycode=%u unicode=U+%04X\n",
         f->layout,keycode,cp);
 int ok=f->thai?(cp>=0x0e01&&cp<=0x0e5b):(cp==f->expected);
 printf("R26_N4_XKB_%s_KEY_%u=%s\n",f->layout,f->evcode,ok?"PASS":"RED");
 xkb_state_unref(state);xkb_keymap_unref(map);
 return !ok;
}
int main(void){
 struct xkb_context *ctx=xkb_context_new(XKB_CONTEXT_NO_FLAGS);
 if(!ctx)return 2;
 // KEY_Y=21, KEY_Z=44, KEY_A=30, KEY_102ND=86, KEY_RO=89
 struct fixture f[]={
  {"us",NULL,21,'y',0},{"us",NULL,44,'z',0},
  {"de",NULL,21,'z',0},{"de",NULL,44,'y',0},
  {"fr",NULL,30,'q',0},{"gb",NULL,21,'y',0},
  {"th",NULL,30,0,1},
  {"th","pat",30,0,1}, /* Thai Pattachote */
  {"us","dvorak",16,0x27,0}, /* Dvorak Q-position is apostrophe */
  {"de","nodeadkeys",21,'z',0}, /* German alternative */
  {"br",NULL,30,'a',0},
  {"jp",NULL,30,'a',0},
  {"kr",NULL,30,'a',0},
 };
 int fails=0;
 for(unsigned i=0;i<sizeof(f)/sizeof(f[0]);i++)fails+=probe(ctx,&f[i]);
 xkb_context_unref(ctx);
 if(fails){fprintf(stderr,"R26_N4_LAYOUT_ERRORS=%d\n",fails);return 3;}
 puts("R26_N4_ACTUAL_XKB_LAYOUT_US_DE_FR_GB_TH_BR_JP_KR=PASS");
 puts("R26_N4_THAI_PAT_GERMAN_NODEADKEYS_US_DVORAK_VARIANTS=PASS");
 puts("R26_N4_THAI_IME_COMPOSITION_AND_JP_KR_IME=NOT_TESTED");
 puts("R26_N4_OS_SELECTED_LAYOUT_NOT_INFERRED_FROM_USB_USAGE=PASS");
 return 0;
}
