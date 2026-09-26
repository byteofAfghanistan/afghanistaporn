                                                                               

                                                                              
                                                                                   
                                                                             
                                                                             
                                                
   
import argparse
import json

from install_source_art import install_exact_aliases
from source_texture_consumer_guard import verify_elite_consumers

SOURCE_NAME = 'sil_MK_huntsman_shark_n_lod2.dd'
SOURCE_SHA = '375536bd45ea6ec0587efa08c1cbd4159376a10da05f6e3e6216472f54583d09'
ALIASES = ('sil_MK_huntsman_shark_n_lod2.dds',)
GRAFFITI_SOURCE_NAME = 'sut_FC_P_graf.dds'
GRAFFITI_SOURCE_SHA = 'f5abbbeba0bb9efe5c58ed8f0a842cf36a199b4c743dbd71a0d8297b834c3fa3'
GRAFFITI_ALIASES = ('sut_FC_P_graf_lod2.dds',)
ELITE_SOURCE_NAME = 'sn_SS_susD_n.dds'
ELITE_SOURCE_SHA = '7a4145510944fa34a9e606144ea3cd6d6b5750965b870498c6c05b996abf2306'
ELITE_ALIASES = ('sut_LZ_otto_n_lod2.dds',)


def install(game_directory, *, check=False, source_reader=None):
    return install_exact_aliases(game_directory, archive_name='txt_weap19.gen',
        source_name=SOURCE_NAME, source_sha=SOURCE_SHA, aliases=ALIASES,
        byte_size=262272, dimensions=(512,512), check=check, source_reader=source_reader)


def install_graffiti(game_directory, *, check=False, source_reader=None):
    result = install_exact_aliases(game_directory, archive_name='txt_weap18.gen',
        source_name=GRAFFITI_SOURCE_NAME, source_sha=GRAFFITI_SOURCE_SHA, aliases=GRAFFITI_ALIASES,
        byte_size=43832, dimensions=(256,256), check=check, source_reader=source_reader)
    result['policy'] = 'same-item-original-high-resolution-texture-alias'
    return result


def install_elite(game_directory, *, check=False, source_reader=None):
                                                                            
                                                                             
                                                                              
    guard = verify_elite_consumers(game_directory)
    result = install_exact_aliases(game_directory, archive_name='txt_weap14.gen',
        source_name=ELITE_SOURCE_NAME, source_sha=ELITE_SOURCE_SHA, aliases=ELITE_ALIASES,
        byte_size=43832, dimensions=(256,256), check=check, source_reader=source_reader)
    result['policy'] = 'same-card-original-normal-with-pinned-consumer-scope'
    result['consumerGuard'] = guard
    return result


def install_all(game_directory, *, check=False, source_reader=None):
                                                                               
                                                                               
    return {'version': 3, 'repairs': [
        install(game_directory, check=check, source_reader=source_reader),
        install_graffiti(game_directory, check=check, source_reader=source_reader),
        install_elite(game_directory, check=check, source_reader=source_reader)]}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--game-dir',required=True)
    parser.add_argument('--check',action='store_true')
    args=parser.parse_args()
    print(json.dumps(install_all(args.game_dir,check=args.check),ensure_ascii=False))


if __name__ == '__main__':main()
