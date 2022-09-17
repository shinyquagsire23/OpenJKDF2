import idautils
import idaapi
import ida_enum
import sys,math

class enumClass(object):

    @staticmethod
    def count():
        '''Return the total number of enumerations'''
        return idaapi.get_enum_qty()

    @staticmethod
    def iterate():
        '''Yield the identifier of each defined enumeration'''
        for n in range(0, idaapi.get_enum_qty()):
            yield idaapi.getn_enum(n)
        return
    
    @staticmethod
    def byName(name):
        '''Return an enum id by it's /name/'''
        res = idaapi.get_enum(name)
        if res == idaapi.BADADDR:
            raise Exception("enumClass.byName(%r):unable to locate enumeration"% name)
        return res

    @staticmethod
    def byIndex(index):
        '''Return an enum id by it's /index/'''
        res = idaapi.getn_enum(index)
        if res == idaapi.BADADDR:
            raise Exception("enumClass.byIndex(%x):unable to locate enumeration"% index)
        return res

    @staticmethod
    def by(n):
        if type(n) is str:
            return byName(n)
    #    if n & 0xff000000 == 0xff000000:
    #        return n
        return byIndex(n)

    @staticmethod
    def keys(identifier):
        '''Given an enum id, return the names of all of it's elements.'''
        return [member.name(n) for n in member.each(identifier)]

    @staticmethod
    def values(identifier):
        '''Given an enum id, return all of it's defined values'''
        return [member.value(n) for n in member.each(identifier)]

    ## creation/deletion
    @staticmethod
    def create(name, flags=0):
        '''Create an enumeration with the specified /name/'''
        idx = count()
        res = idaapi.add_enum(idx, name, flags)
        if res == 0xffffffff:
            raise Exception("Unable to create enum")
        return res

    @staticmethod
    def _delete(identifier):
        return idaapi.del_enum(identifier)

    @staticmethod
    def delete(name):
        '''Delete an enumeration by it's /name/'''
        identifier = byName(name)
        return _delete(identifier)
    new,remove = create,delete

    ## setting enum options
    @staticmethod
    def name(identifier, name=None):
        '''Given an enum id, get/set it's /name/'''
        if name is None:
            return idaapi.get_enum_name(identifier)
        return idaapi.set_enum_name(identifier, name)
    
    @staticmethod
    def comment(identifier, comment=None):
        '''Given an enum id, get/set it's /comment/'''
        if commment is None:
            return idaapi.get_enum_cmt(identifier)
        return idaapi.set_enum_cmt(identifier, comment)
    
    @staticmethod
    def size(identifier, width=None):
        '''Given an enum id, get/set it's size'''
        if width is None:
            res = idaapi.get_enum_width(identifier)
            return 2**(res-1) if res > 0 else 0
        res = int(math.log(width, 2))
        return idaapi.set_enum_width(identifier, int(res)+1)
    
    @staticmethod
    def mask(identifier):
        '''Given an enum id, return it's bitmask'''
        res = min((enumClass.size(identifier), 4))    # FIXME: is uval_t/bmask_t a maximum of 32bits on ida64 too?
        if res > 0:
            return 2**(res*8)-1
        return 0xFFFFFFFF

    @staticmethod
    def members(identifier):
        '''Given an enum id, yield each member's name'''
        for n in member.each(identifier):
            yield member.name(n)
        return

    @staticmethod
    def repr(identifier):
        '''Given an enum id, return a representation of it suitable for human consumption'''
        w = enumClass.size(identifier)*2
        result = [(member.name(n),member.value(n),member.bmask(n),member.comment(n)) for n in member.each(identifier)]
        aligned = max((len(n) for n,_,_,_ in result))
        return "<type 'enum'> {:x}\n".format(identifier) + '\n'.join((' {:<{align}s} : {:0{width}x}'.format(name,value,width=w,align=aligned)+((' # '+comment) if comment else '') for name,value,bmask,comment in result))

## members
class member(object):
    '''This class allows one to interact with the members of a defined enumeration.
    Examples:
        e = enumClass.byName('example_enumeration')
        print enumClass.repr(e)
        enumClass.member.rename(e, 'oldname', 'newname')
        n = enumClass.member.add(e, 'name', 0x1000)
        enumClass.member.remove(n)
        n = enumClass.member.byName(e, 'name')
        n = enumClass.member.byValue(e, 0x1000)
        enumClass.member.name(n, 'somename')
        enumClass.member.value(n, 0x100)
        enumClass.member.comment(n, 'This is an test value')
        for n in enumClass.member.each(e):
            print enumClass.member.name(n)
            print enumClass.member.value(n)
            print enumClass.member.comment(n)
    '''

    @staticmethod
    def parent(identifier):
        '''Given a member id, return the enum id that is associated with it'''
        return idaapi.get_enum_member_enum(identifier)

    ## lifetime
    @classmethod
    def add(cls, enum, name, value, **kwds):
        '''Given a valid enum id, add the specified /name/ and /value/ to it'''
        bmask = kwds.get('mask', -1&enumClass.mask(enum))
        res = idaapi.add_enum_member(enum, name, value, bmask)
        if res in (idaapi.ENUM_MEMBER_ERROR_NAME, idaapi.ENUM_MEMBER_ERROR_VALUE, idaapi.ENUM_MEMBER_ERROR_ENUM, idaapi.ENUM_MEMBER_ERROR_MASK, idaapi.ENUM_MEMBER_ERROR_ILLV):
            raise Exception("enumClass.member.add(%x, %r, %r, %r):Unable to add enum member"%(enum, name, value, kwds))
        return cls.byValue(enum, value)
    new = create = add

    @classmethod
    def _remove(cls, identifier):
        '''Given a member id, remove it from it's enumeraiton'''
        value = cls.value(identifier)
        # XXX: is a serial of 0 valid?
        res = idaapi.del_enum_member(cls.parent(identifier), value, 0, -1&cls.bmask(identifier))
        if not res:
            raise Exception("enumClass.member._remove(%x):Unable to remove enum member"% identifier)
        return res
    _delete = _destroy = _remove
    @classmethod
    def remove(cls, enum, name):
        '''Given an enum id, remove it's member called /name/'''
        identifier = cls.byName(enum, name)
        return cls._remove(identifier)
    delete = destroy = remove
    
    @staticmethod
    def _each(enum):
        bmask = -1&enumClass.mask(enum)
        res = idaapi.get_first_enum_member(enum, bmask)
        yield res
        while res != idaapi.get_last_enum_member(enum, bmask):
            res = idaapi.get_next_enum_member(enum, res, bmask)
            yield res
        return
    @classmethod
    def each(cls, enum):
        '''Given an enum id, yield each id of it's members'''
        bmask = -1&enumClass.mask(enum)
        for v in cls._each(enum):
            res,_ = idaapi.get_first_serial_enum_member(enum, v, bmask)
            # XXX: what does get_next_serial_enum_member and the rest do?
            yield res
        return

    ## searching
    @staticmethod
    def byValue(enum, value):
        '''Given an enum id, return the member id with the specified /value/'''
        bmask = -1&enumClass.mask(enum)
        res,_ = idaapi.get_first_serial_enum_member(enum, value, bmask)
        return res
    @classmethod
    def byName(cls, enum, name):
        '''Given an enum id, return the member id of /name/'''
        for identifier in cls.each(enum):
            if name == cls.name(identifier):
                return identifier
            continue
        return

    ## properties
    @staticmethod
    def name(identifier, name=None):
        '''Given a member id, fetch/set it's /name/'''
        if name is None:
            return idaapi.get_enum_member_name(identifier)
        return idaapi.set_enum_member_name(identifier, name)
    @classmethod
    def rename(cls, enum, name, newname):
        '''Given an enumeration id, rename one of it's members from /name/ to /newname/'''
        identifier = member.byName(enum, name)
        return cls.name(identifier, newname)

    @staticmethod
    def comment(identifier, comment=None, repeatable=True):
        '''Given a member id, fetch/set it's /comment/'''
        if comment is None:
            return idaapi.get_enum_member_cmt(identifier, repeatable)
        return idaapi.set_enum_member_cmt(identifier, comment, repeatable)

    @staticmethod
    def value(identifier, value=None, **kwds):
        '''Given a member id, fetch/set it's /value/'''
        if value is None:
            return idaapi.get_enum_member_value(identifier)
        bmask = kwds.get('mask', -1&enumClass.mask(enum))
        return idaapi.set_enum_member_value(identifier, value, bmask)

    @staticmethod
    def serial(identifier):
        '''Given a member id, return it's serial'''
        return idaapi.get_enum_member_serial(identifier)

    @staticmethod
    def bmask(identifier):
        '''Given a member id, return it's bmask'''
        return idaapi.get_enum_member_bmask(identifier)


enum_name = "DSS_ID"
rename_prefix_from = "COGMSG_"
rename_prefix_to = "DSS_"

e = enumClass.byName(enum_name)
print(enumClass.name(e))
print(enumClass.size(e), enumClass.mask(e))

def rename_all_in_enum(e, prefix_from, prefix_to):
    for m in member.each(e):
        name = member.name(m)
        if name == None: continue

        #print (member.name(m))
        member.name(m, name.replace(prefix_from, prefix_to))

rename_all_in_enum(e, rename_prefix_from, rename_prefix_to)

#for e in enumClass.iterate():
#    rename_all_in_enum(e, rename_prefix_from, rename_prefix_to)