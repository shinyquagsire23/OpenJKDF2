#include "rdMath.h"

float __cdecl rdMath_DistancePointToPlane(rdVector3 *light, rdVector3 *normal, rdVector3 *vertex)
{
  return (light->y - vertex->y) * normal->y + (light->z - vertex->z) * normal->z + (light->x - vertex->x) * normal->x;
}
