/* New packets append a sound filename to the original payload. Keep the old
 * layout for saved-game messages, but never substitute a local index when an
 * explicit name is unavailable: sound tables can differ between peers. */
static sithSound *sithDSSSound_Resolve(const SithMessage *message, unsigned int legacySize, unsigned int index)
{
    char name[32];
    if (message->netMsg.msg_size == legacySize)
        return index == 0xffffu ? NULL : sithSound_GetFromIdx((int)index);
    if (message->netMsg.msg_size != legacySize + sizeof(name))
        return NULL;
    memcpy(name, (const unsigned char*)message->pktData + legacySize, sizeof(name));
    if (!memchr(name, 0, sizeof(name)) || !name[0])
        return NULL;
    /* Network resource names must stay inside the game's search paths. */
    if (strstr(name, "..") || strchr(name, ':') || name[0] == '/' || name[0] == '\\')
        return NULL;
    return sithSound_Load(name, 0);
}
