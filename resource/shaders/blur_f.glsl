uniform sampler2D tex;
uniform vec2 iResolution;
uniform float param1;
uniform float param2;
uniform float param3;
in vec4 f_color;
in vec2 f_uv;
in vec3 f_coord;
out vec4 fragColor;

void main(void)
{
    float Pi = 6.28318530718; // Pi*2
    
    // GAUSSIAN BLUR SETTINGS {{{
    float Directions = param1; // BLUR DIRECTIONS (Default 16.0 - More is better but slower)
    float Quality = param2; // BLUR QUALITY (Default 4.0 - More is better but slower)
    float Size = param3; // BLUR SIZE (Radius)
    // GAUSSIAN BLUR SETTINGS }}}
   
    vec2 Radius = Size/iResolution.xy;
    
    // Pixel colour
    vec4 Color = texture(tex, f_uv, 1.0);
    
    // Blur calculations
    // Added: integer counters. Stepping floats by Pi/Directions and 1.0/Quality left the sample
    // count to rounding, and on some GPUs the last ring (i == 1.0) was skipped on some frames.
    // That dropped the blur's alpha to about 0.75, and the combine scaled the 3D view by it.
    int nDirections = int(Directions + 0.5);
    int nQuality = int(Quality + 0.5);
    for (int di = 0; di < nDirections; di++)
    {
        float d = float(di) * Pi / Directions;
        for (int qi = 1; qi <= nQuality; qi++)
        {
            float i = float(qi) / Quality;
            Color += texture( tex, f_uv+vec2(cos(d),sin(d))*Radius*i, 1.0);     
        }
    }
    
    // Output to screen
    Color /= Quality * Directions;// - (Directions == 16.0 ? 15.0 : 0.0); // HACK

    fragColor = Color;
    //fragColor.a = 1.0;

    //fragColor = vec4(1.0, 1.0, 0.0, 0.5);
}
