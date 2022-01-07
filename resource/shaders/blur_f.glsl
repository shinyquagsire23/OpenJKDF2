uniform sampler2D tex;
uniform vec2 iResolution;
in vec4 f_color;
in vec2 f_uv;
in vec3 f_coord;
out vec4 fragColor;

void main(void)
{
    float Pi = 6.28318530718; // Pi*2
    
    // GAUSSIAN BLUR SETTINGS {{{
    float Directions = 16.0; // BLUR DIRECTIONS (Default 16.0 - More is better but slower)
    float Quality = 3.0; // BLUR QUALITY (Default 4.0 - More is better but slower)
    float Size = 12.0; // BLUR SIZE (Radius)
    // GAUSSIAN BLUR SETTINGS }}}
   
    vec2 Radius = Size/iResolution.xy;
    
    // Pixel colour
    vec4 Color = texture(tex, f_uv);
    
    // Blur calculations
    for( float d=0.0; d<Pi; d+=Pi/Directions)
    {
        for(float i=1.0/Quality; i<=1.0; i+=1.0/Quality)
        {
            Color += texture( tex, f_uv+vec2(cos(d),sin(d))*Radius*i);      
        }
    }
    
    // Output to screen
    Color /= Quality * Directions - 15.0;

    fragColor =  Color;

    //fragColor = vec4(1.0, 1.0, 0.0, 0.5);
}
