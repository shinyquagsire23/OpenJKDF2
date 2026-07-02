// Dreamcast CPU fault reporter.
//
// Catches SH4 exceptions (bad reads/writes, illegal opcodes, double faults,
// anything otherwise unhandled) and reports PC/PR/faulting-address on screen --
// KOS's default handler only prints to the serial console, which is invisible on
// a TV. Primary output is text drawn straight into the currently-displayed
// framebuffer; a border-color blink sequence is the fallback for display configs
// where the framebuffer text isn't visible. Map addresses back to source with
// `sh-elf-addr2line -e openjkdf2.elf <PC>`.
//
// Everything in the fault path is freestanding: no KOS/newlib calls. bfont_draw_*
// takes the BIOS font lock via thd_poll() per glyph, and thd_poll() asserts
// !irq_inside_int() -- which is always true inside an exception handler (irq.c
// sets inside_int before dispatch), so the first character drawn would abort
// inside the handler. vsnprintf is also out (newlib reentrancy + a ~2KB appetite
// on KOS's 4KB static exception stack). Instead the ROM font pointer is cached at
// install time (normal context) and glyphs are blitted by hand: pure reads from
// ROM, pure 16-bit writes to VRAM.

#ifdef TARGET_DREAMCAST

#include "dcFault.h"

#include <kos.h>
#include <dc/pvr.h>
#include <dc/video.h>
#include <dc/syscalls.h>
#include <arch/irq.h>

// One blink "unit" as a busy-loop count (~1/3 s at 200 MHz -- filmable; exact timing
// doesn't matter, only the color sequence does). Interrupts are off in the handler so
// timers aren't available.
#define DCFAULT_BLINK_UNIT 10000000u
static void dcFault_Spin(uint32_t loops) { for (volatile uint32_t i = 0; i < loops; i++) { } }

// Blink a 32-bit value on the TV border, MSB first, as 8 hex nibbles. Each nibble is a
// GREEN start marker, then its 4 bits MSB-first as RED=1 / BLUE=0 (both lit, so there's
// no "black == 0" ambiguity), each bit followed by a short black gap. To decode: after
// the intro color, read 8 groups; each group is GREEN then 4 colored pulses => 1 hex
// digit; concatenate the 8 digits.
static void dcFault_BlinkWord(uint32_t val)
{
    for (int nib = 7; nib >= 0; nib--) {
        uint32_t n = (val >> (nib * 4)) & 0xF;
        vid_border_color(0, 255, 0); dcFault_Spin(DCFAULT_BLINK_UNIT);       // GREEN: nibble start
        vid_border_color(0, 0, 0);   dcFault_Spin(DCFAULT_BLINK_UNIT / 2);
        for (int bit = 3; bit >= 0; bit--) {
            if (n & (1u << bit)) vid_border_color(255, 0, 0);                // RED  = 1
            else                 vid_border_color(0, 0, 255);                // BLUE = 0
            dcFault_Spin(DCFAULT_BLINK_UNIT);
            vid_border_color(0, 0, 0); dcFault_Spin(DCFAULT_BLINK_UNIT / 2); // gap between bits
        }
    }
}

static const uint8_t* dcFault_pFont = NULL; // BIOS ROM font; syscall'd once at install

// Blit one thin BIOS-font glyph (12x24, 3 bytes per two 12-bit rows) as RGB565.
static void dcFault_DrawChar(uint16_t* dst, char c, uint16_t color)
{
    if (!dcFault_pFont || c < 33 || c > 126) return; // space/unknown: leave cell
    const uint8_t* g = dcFault_pFont + (c - 32) * 36;
    for (int y = 0; y < 24; y += 2, g += 3) {
        uint16_t row0 = ((uint16_t)g[0] << 4) | (g[1] >> 4);
        uint16_t row1 = (((uint16_t)g[1] << 8) & 0xF00) | g[2];
        for (int x = 0; x < 12; x++) {
            if (row0 & (0x800 >> x)) dst[x] = color;
            if (row1 & (0x800 >> x)) dst[640 + x] = color;
        }
        dst += 640 * 2;
    }
}

static void dcFault_DrawStr(uint16_t* fb, int x, int y, uint16_t color, const char* s)
{
    for (; *s; s++, x += 12) dcFault_DrawChar(fb + y * 640 + x, *s, color);
}

static void dcFault_DrawHex(uint16_t* fb, int x, int y, uint16_t color, uint32_t val)
{
    static const char hex[] = "0123456789ABCDEF";
    for (int nib = 7; nib >= 0; nib--, x += 12)
        dcFault_DrawChar(fb + y * 640 + x, hex[(val >> (nib * 4)) & 0xF], color);
}

// Never returns -- the game is wedged anyway.
static void dcFault_Handler(irq_t code, irq_context_t* ctx, void* data)
{
    (void)data;
    // Border red first: a pure register write that can't fault, so even if
    // something below wedges there's visible evidence the handler fired.
    vid_border_color(255, 0, 0);

    uint32_t tea = *(volatile uint32_t*)0xFF00000C; // SH4 TEA: faulting data address
    const char* kind = (code == EXC_DATA_ADDRESS_WRITE) ? "WRITE" :
                       (code == EXC_DATA_ADDRESS_READ)  ? "READ" :
                       (code == EXC_ILLEGAL_INSTR)      ? "ILLEGAL OPCODE" :
                       (code == EXC_DOUBLE_FAULT)       ? "DOUBLE FAULT" : "OTHER";

    // Write into the scanned-out framebuffer, read directly from the PVR display
    // register: PVR_FB_ADDR is the displayed buffer's VRAM offset and PVR_RAM_BASE is
    // the linear 32-bit P2 area (KOS's vram_s mechanism). Unlike vid_set_mode (waits on
    // a vblank IRQ that can't fire here) and pvr_get_front_buffer (its irq_disable_scoped
    // re-faults), this is a plain register read + linear VRAM writes -- exception-safe.
    uint16_t* fb = (uint16_t*)(PVR_RAM_BASE | (PVR_GET(PVR_FB_ADDR) & (PVR_RAM_SIZE - 1)));
    for (int y = 24; y < 200; y++)
        for (int x = 0; x < 640; x++) fb[y * 640 + x] = 0x0000; // dark band behind text
    dcFault_DrawStr(fb, 24, 40, 0xFFFF, "OpenJKDF2 CPU FAULT: ");
    dcFault_DrawStr(fb, 24 + 21 * 12, 40, 0xFFFF, kind);
    dcFault_DrawStr(fb, 24, 72, 0xFFE0, "evt  = ");
    dcFault_DrawHex(fb, 24 + 7 * 12, 72, 0xFFE0, (uint32_t)code);
    dcFault_DrawStr(fb, 24, 96, 0xFFE0, "PC   = ");
    dcFault_DrawHex(fb, 24 + 7 * 12, 96, 0xFFE0, ctx->pc);
    dcFault_DrawStr(fb, 24, 120, 0xFFE0, "PR   = ");
    dcFault_DrawHex(fb, 24 + 7 * 12, 120, 0xFFE0, ctx->pr);
    dcFault_DrawStr(fb, 24, 144, 0xFFE0, "addr = ");
    dcFault_DrawHex(fb, 24 + 7 * 12, 144, 0xFFE0, tea);

    // Fallback: also blink the registers out on the border (proven on hardware), in case
    // the framebuffer text isn't visible on some display config. Decode via BlinkWord.
    for (;;) {
        vid_border_color(255, 255, 255); dcFault_Spin(DCFAULT_BLINK_UNIT * 5); // WHITE = PC next
        dcFault_BlinkWord(ctx->pc);
        vid_border_color(255, 255, 0);   dcFault_Spin(DCFAULT_BLINK_UNIT * 5); // YELLOW = PR next
        dcFault_BlinkWord(ctx->pr);
        vid_border_color(255, 0, 255);   dcFault_Spin(DCFAULT_BLINK_UNIT * 5); // MAGENTA = addr next
        dcFault_BlinkWord(tea);
    }
}

void dcFault_Install(void)
{
    static int bInstalled = 0;
    if (bInstalled) return;
    bInstalled = 1;

    // Cache the BIOS ROM font pointer now, from normal context; the handler
    // itself must not make this syscall (see dcFault_DrawChar).
    dcFault_pFont = syscall_font_address();

    arch_irq_set_handler(EXC_DATA_ADDRESS_READ,  dcFault_Handler, NULL);
    arch_irq_set_handler(EXC_DATA_ADDRESS_WRITE, dcFault_Handler, NULL);
    arch_irq_set_handler(EXC_ILLEGAL_INSTR,      dcFault_Handler, NULL);
    // Catch-alls: EXC_UNHANDLED_EXC covers everything not enumerated above (FPU
    // exceptions, TLB misses, slot-illegal, ...) and EXC_DOUBLE_FAULT covers faults
    // inside an ISR -- KOS would otherwise arch_panic to the serial console, which
    // is invisible on a TV. UNHANDLED passes the real evt code through;
    // DOUBLE_FAULT passes 0x780 (shown on screen). Safe because the handler is
    // freestanding (no KOS calls that could re-fault).
    arch_irq_set_handler(EXC_UNHANDLED_EXC,      dcFault_Handler, NULL);
    arch_irq_set_handler(EXC_DOUBLE_FAULT,       dcFault_Handler, NULL);
}

#endif // TARGET_DREAMCAST
