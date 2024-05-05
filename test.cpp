#include <filesystem>
#include <iostream>
#include <ostream>
#include <thread> // NOLINT
#include <vector>

void printParamInfo(u64 setSize, u64 numFeatures, u64 numHash, u64 numThreads, u64 cSecParam,
                    u64 StaParam) // 参数设置
{
    std::cout << "set size: " << setSize << std::endl
              << "numFeatures: " << numFeatures << std::endl
              << "numHash: " << numHash << std::endl
              << "numThreads: " << numThreads << std::endl
              << "computation security parameters: " << cSecParam << std::endl
              << "statistical security parameters: " << StaParam << std::endl
              << std::endl
              << std::endl;
}

void printInfo()
{
    std::cout << oc::Color::Green
              << "###############################################################"
                 "######\n"
              << "###############################################################"
                 "######\n"
              << "#                                                              "
                 "     #\n"
              << "#                      IP Private Union                        "
                 "     #\n"
              << "#                                                              "
                 "     #\n"
              << "###############################################################"
                 "######\n"
              << "###############################################################"
                 "######\n"
              << oc::Color::Default;
    std::cout << oc::Color::Blue << "Parameter description: \n"
              << oc::Color::Green << "-iprunion: Run the ip private Union.\n" // ip private union
              << "      -m: input set size ( 2^m ).\n"
              << "      -nf: input number of features ( nf ).\n"
              << "      -nh: input number of hashes ( nf ).\n"
              << "      -t: number of threads.\n"
              // << "      -u: Run unit test.\n"
              << "-cpsi: Run  RS21 circuit psi.\n" // cpsi
              << "      -m <value>: the log2 size of the sets.\n"
              << "      -st: ValueShareType (1 xor,0 add32).\n"
              << "      -t: number of threads.\n"
              << oc::Color::Default;
}

int main(int argc, char **argv)
{
    oc::CLP cmd(argc, argv); // 命令行输入参数
    if (cmd.isSet("cpsi"))
    {
        cpsi(cmd);
    }
    else if (cmd.isSet("iprunion"))
    {
        iprunion(cmd);
    }
    else
        printInfo();

    return 0;
}