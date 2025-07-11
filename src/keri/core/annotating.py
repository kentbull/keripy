# -*- coding: utf-8 -*-
"""
keri.core.annotating module

Provides support for Annotater
"""


from typing import NamedTuple
from collections import namedtuple

from .. import kering
from ..kering import sniff, Colds, Ilks

from ..help.helping import intToB64



from .. import help

from . import coring
from .coring import (Matter, Verser, Ilker, Diger, Prefixer, Number, Tholder,
                     Verfer, Traitor)

from . import counting
from .counting import Counter

from .structing import Sealer
from .serdering import Serder


def annot(ims):
    """Annotate CESR stream

    Returns:
        annotation (str):  annotation of input CESR stream

    Parameters:
        ims (str | bytes | bytearray | memoryview): CESR incoming message stream
           as qb64  (maybe qb2)

    """
    oms = bytearray()
    indent = 0


    if not isinstance(ims, bytearray):  # going to strip
        ims = bytearray(ims)  # so make bytearray copy, converts str to bytearray

    while ims:  # right now just for KERI event messages
        cold = sniff(ims)  # check for spurious counters at front of stream

        if cold in Colds.txt:
            val = Counter(qb64b=ims, strip=True)
            oms.extend(f"{' ' * indent * 2}{val.qb64} # Key Event Counter "
                       f"{val.name} count={val.count} quadlets\n".encode())
            indent += 1

            # should grab fill message frame here so can verify its consumed
            # when done annotating

            # version
            val = Verser(qb64b=ims, strip=True)
            versage = val.versage
            oms.extend(f"{' ' * indent * 2}{val.qb64} # 'v' version  Verser {val.name} "
                       f"proto={versage.proto} vrsn={versage.pvrsn.major}."
                       f"{versage.pvrsn.minor:02}\n".encode())
            # ilk
            ilker = Ilker(qb64b=ims, strip=True)
            ilk = ilker.ilk
            oms.extend(f"{' ' * indent * 2}{ilker.qb64} # 't' message type Ilker "
                       f"{ilker.name} Ilk={ilker.ilk}\n".encode())



            if ilk in (Ilks.icp, Ilks.ixn, Ilks.rot, Ilks.dip, Ilks.drt):
                # said
                val = Diger(qb64b=ims, strip=True)
                oms.extend(f"{' ' * indent * 2}{val.qb64} # 'd' SAID Diger "
                           f"{val.name} \n".encode())

                # aid pre
                val = Prefixer(qb64b=ims, strip=True)
                oms.extend(f"{' ' * indent * 2}{val.qb64} # 'i' AID Prefixer "
                           f"{val.name} \n".encode())

                # sn
                val = Number(qb64b=ims, strip=True)
                oms.extend(f"{' ' * indent * 2}{val.qb64} # 's' Number "
                           f"{val.name} sn={val.sn}\n".encode())

            if ilk in (Ilks.icp, Ilks.dip):  # inception
                # v='', t='', d='', i='', s='0', kt='0',k=[], nt='0', n=[], bt='0', b=[], c=[], a=[]

                # Signing key threshold
                val = Tholder(limen=ims, strip=True)  # add qb64 and qb2 to tholder as aliases for limen and limen.decode()
                oms.extend(f"{' ' * indent * 2}{val.limen.decode()} # 'kt' "
                           f"Tholder signing threshold={val.sith}\n".encode())
                # Signing key list
                val = Counter(qb64b=ims, strip=True)
                oms.extend(f"{' ' * indent * 2}{val.qb64} # 'k' Signing Key "
                           f"List Counter {val.name} count={val.count} quadlets\n".encode())
                indent += 1
                frame = ims[:val.count*4]  # extract frame from ims
                del ims[:val.count*4]  # strip frame
                while frame:
                    val = Verfer(qb64b=frame, strip=True)
                    oms.extend(f"{' ' * indent * 2}{val.qb64} # key Verfer "
                               f"{val.name}\n".encode())
                indent -= 1
                # Rotation key threshold
                val = Tholder(limen=ims, strip=True)
                oms.extend(f"{' ' * indent * 2}{val.limen.decode()} # 'nt' "
                           f"Tholder rotation threshold={val.sith}\n".encode())
                # Next key digest list
                val = Counter(qb64b=ims, strip=True)
                oms.extend(f"{' ' * indent * 2}{val.qb64} # 'n' Rotation Key "
                           f"Digest List Counter {val.name} count={val.count} "
                           f"quadlets\n".encode())
                indent += 1
                frame = ims[:val.count*4]  # extract frame from ims
                del ims[:val.count*4]  # strip frame
                while frame:
                    val = Diger(qb64b=frame, strip=True)
                    oms.extend(f"{' ' * indent * 2}{val.qb64} # key digest Diger"
                               f" {val.name}\n".encode())
                indent -= 1
                # Witness Backer threshold
                val = Tholder(limen=ims, strip=True)
                oms.extend(f"{' ' * indent * 2}{val.limen.decode()} # 'bt' "
                           f"Tholder Backer (witness) threshold={val.sith}\n".encode())
                # Witness Backer list
                val = Counter(qb64b=ims, strip=True)
                oms.extend(f"{' ' * indent * 2}{val.qb64} # 'b' Backer (witness)"
                           f"List Counter {val.name} count={val.count} quadlets\n".encode())
                indent += 1
                frame = ims[:val.count*4]  # extract frame from ims
                del ims[:val.count*4]  # strip frame
                while frame:
                    val = Prefixer(qb64b=frame, strip=True)
                    oms.extend(f"{' ' * indent * 2}{val.qb64} # AID Prefixer "
                               f"{val.name}\n".encode())
                indent -= 1
                # Config Trait List
                val = Counter(qb64b=ims, strip=True)
                oms.extend(f"{' ' * indent * 2}{val.qb64} # 'c' Config Trait "
                           f"List Counter {val.name} count={val.count} quadlets\n".encode())
                indent += 1
                frame = ims[:val.count*4]  # extract frame from ims
                del ims[:val.count*4]  # strip frame
                while frame:
                    val = Traitor(qb64b=frame, strip=True)
                    oms.extend(f"{' ' * indent * 2}{val.qb64} # trait Traitor "
                               f"{val.name} trait={val.trait}\n".encode())
                indent -= 1


            elif ilk == Ilks.ixn:  # Interaction
                # v='', t='',d='', i='', s='0', p='', a=[]
                # Prior said
                val = Diger(qb64b=ims, strip=True)
                oms.extend(f"{' ' * indent * 2}{val.qb64} # 'p' prior SAID Diger "
                           f"{val.name} \n".encode())



            elif ilk in (Ilks.rot, Ilks.drt):  # Rotation
                # v='', t='',d='', i='', s='0', p='', kt='0',k=[], nt='0', n=[], bt='0', br=[], ba=[], c=[], a=[]
                # Prior said
                val = Diger(qb64b=ims, strip=True)
                oms.extend(f"{' ' * indent * 2}{val.qb64} # 'p' prior SAID Diger "
                           f"{val.name} \n".encode())

                # Signing key threshold
                val = Tholder(limen=ims, strip=True)  # add qb64 and qb2 to tholder as aliases for limen and limen.decode()
                oms.extend(f"{' ' * indent * 2}{val.limen.decode()} # 'kt' "
                           f"Tholder signing threshold={val.sith}\n".encode())
                # Signing key list
                val = Counter(qb64b=ims, strip=True)
                oms.extend(f"{' ' * indent * 2}{val.qb64} # 'k' Signing Key "
                           f"List Counter {val.name} count={val.count} quadlets\n".encode())
                indent += 1
                frame = ims[:val.count*4]  # extract frame from ims
                del ims[:val.count*4]  # strip frame
                while frame:
                    val = Verfer(qb64b=frame, strip=True)
                    oms.extend(f"{' ' * indent * 2}{val.qb64} # key Verfer "
                               f"{val.name}\n".encode())
                indent -= 1
                # Rotation key threshold
                val = Tholder(limen=ims, strip=True)
                oms.extend(f"{' ' * indent * 2}{val.limen.decode()} # 'nt' "
                           f"Tholder rotation threshold={val.sith}\n".encode())
                # Next key digest list
                val = Counter(qb64b=ims, strip=True)
                oms.extend(f"{' ' * indent * 2}{val.qb64} # 'n' Rotation Key "
                           f"Digest List Counter {val.name} count={val.count} "
                           f"quadlets\n".encode())
                indent += 1
                frame = ims[:val.count*4]  # extract frame from ims
                del ims[:val.count*4]  # strip frame
                while frame:
                    val = Diger(qb64b=frame, strip=True)
                    oms.extend(f"{' ' * indent * 2}{val.qb64} # key digest Diger"
                               f" {val.name}\n".encode())
                indent -= 1
                # Witness Backer threshold
                val = Tholder(limen=ims, strip=True)
                oms.extend(f"{' ' * indent * 2}{val.limen.decode()} # 'bt' "
                           f"Tholder Backer (witness) threshold={val.sith}\n".encode())

                # Witness Backer Cut list
                val = Counter(qb64b=ims, strip=True)
                oms.extend(f"{' ' * indent * 2}{val.qb64} # 'b' Backer (witness)"
                           f"Cut List Counter {val.name} count={val.count} quadlets\n".encode())
                indent += 1
                frame = ims[:val.count*4]  # extract frame from ims
                del ims[:val.count*4]  # strip frame
                while frame:
                    val = Prefixer(qb64b=frame, strip=True)
                    oms.extend(f"{' ' * indent * 2}{val.qb64} # AID Prefixer "
                               f"{val.name}\n".encode())
                indent -= 1

                # Witness Backer Add list
                val = Counter(qb64b=ims, strip=True)
                oms.extend(f"{' ' * indent * 2}{val.qb64} # 'b' Backer (witness)"
                           f"Add List Counter {val.name} count={val.count} quadlets\n".encode())
                indent += 1
                frame = ims[:val.count*4]  # extract frame from ims
                del ims[:val.count*4]  # strip frame
                while frame:
                    val = Prefixer(qb64b=frame, strip=True)
                    oms.extend(f"{' ' * indent * 2}{val.qb64} # AID Prefixer "
                               f"{val.name}\n".encode())
                indent -= 1

                # Config Trait List
                val = Counter(qb64b=ims, strip=True)
                oms.extend(f"{' ' * indent * 2}{val.qb64} # 'c' Config Trait "
                           f"List Counter {val.name} count={val.count} quadlets\n".encode())
                indent += 1
                frame = ims[:val.count*4]  # extract frame from ims
                del ims[:val.count*4]  # strip frame
                while frame:
                    val = Traitor(qb64b=frame, strip=True)
                    oms.extend(f"{' ' * indent * 2}{val.qb64} # trait Traitor "
                               f"{val.name} trait={val.trait}\n".encode())
                indent -= 1


            else:
                raise kering.IlkError(f"Unexpected message type={ilk}")

            if ilk in (Ilks.icp, Ilks.ixn, Ilks.rot, Ilks.dip, Ilks.drt):
                # Seal (anchor) List
                val = Counter(qb64b=ims, strip=True)
                oms.extend(f"{' ' * indent * 2}{val.qb64} # 'a' Seal List Counter"
                           f" {val.name} count={val.count} quadlets\n".encode())
                indent += 1
                frame = ims[:val.count*4]  # extract frame from ims
                del ims[:val.count*4]  # strip frame
                while frame:
                    val = Counter(qb64b=frame, strip=True)
                    oms.extend(f"{' ' * indent * 2}{val.qb64} # Seal Counter "
                               f"{val.name} count={val.count} quadlets\n".encode())
                    indent += 1
                    subframe = frame[:val.count*4]
                    del frame[:val.count*4]  # strip subframe
                    clan = Sealer.Clans[Serder.CodeClans[val.code]]
                    while subframe:
                        val = Sealer(clan=clan, qb64=subframe, strip=True)  # need to add qb64 parameter to structor
                        oms.extend(f"{' ' * indent * 2}{val.qb64}# seal Sealer {val.name}\n".encode())
                        indent += 1
                        for i, t in enumerate(val.crew._asdict().items()):
                            oms.extend(f"{' ' * indent * 2}#  '{t[0]}' = "
                                   f"{t[1]}\n".encode())
                        indent -= 1
                    indent -= 1
                indent -= 1

            if ilk == Ilks.dip:
                # delegator aid delpre
                val = Prefixer(qb64b=ims, strip=True)
                oms.extend(f"{' ' * indent * 2}{val.qb64} # 'di' Delegator AID Prefixer "
                           f"{val.name} \n".encode())

            if ims:
                raise kering.ExtractionError(f"Unexpected remaining bytes in stream.")

        elif cold in Colds.bny:
            pass

        else:
            raise kering.ColdStartError("Expecting stream tritet={}"
                                        "".format(cold))

    return oms.decode()  # return unicode string

def denot(ams):
    """De-annotate CESR stream

    Returns:
        dms (bytes):  deannotation of input annotated CESR message stream

    Parameters:
        ams (str):  CESR annotated message stream text
    """
    dms = bytearray()  # deannotated message stream
    lines = ams.splitlines()
    for line in lines:
        line = line.strip()
        front, sep, back = line.partition('#') # finde comment if any
        front = front.strip()  # non-commented portion strip white space
        if front:
            dms.extend(front.encode())

    return bytes(dms)



